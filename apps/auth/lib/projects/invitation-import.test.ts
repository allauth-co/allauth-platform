import { APIError } from "better-auth";
import { admin, organization } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { allauthControl } from "../control";
import { projectManagement } from "./management-plugin";

const origin = "https://allauth.example";
const basePath = "/api/projects/fixture-production/auth";
async function setup() {
	const send = vi.fn();
	const state = await getTestInstance(
		{
			baseURL: origin,
			basePath,
			logger: { disabled: true },
			user: {
				additionalFields: {
					directoryDisabled: { type: "boolean", required: false },
				},
			},
			plugins: [
				admin(),
				organization({
					dynamicAccessControl: { enabled: true },
					requireEmailVerificationOnInvitation: true,
					sendInvitationEmail: send,
				}),
				allauthControl(),
				projectManagement({
					projectId: "project-a",
					projectSlug: "fixture-production",
					baseURL: origin,
					requirePlatformAdmin: async (ctx) => {
						if (ctx.headers?.get("x-management-fixture") !== "authorized")
							throw new APIError("FORBIDDEN");
						return {
							user: {
								id: "workspace-owner",
								name: "Owner",
								email: "owner@example.test",
								emailVerified: true,
							},
							session: { id: "root-session", userId: "workspace-owner" },
						};
					},
				}),
			],
		},
		{ disableTestUser: true },
	);
	const context = await state.auth.$context;
	const owner = await state.auth.api.signUpEmail({
		body: {
			email: "inviter@example.test",
			name: "Inviter",
			password: "fixture-password",
		},
	});
	await context.adapter.update({
		model: "user",
		where: [{ field: "id", value: owner.user.id }],
		update: { emailVerified: true },
	});
	const company = await context.adapter.create<{ id: string }>({
		model: "organization",
		data: { name: "Company", slug: "company", createdAt: new Date() },
	});
	await context.adapter.create({
		model: "member",
		data: {
			organizationId: company.id,
			userId: owner.user.id,
			role: "owner",
			createdAt: new Date(),
		},
	});
	const invitation = {
		sourceInvitationId: "local-invite-1",
		organizationId: company.id,
		email: "invitee@example.test",
		role: "member",
		inviterId: owner.user.id,
		expiresAt: new Date(Date.now() + 72 * 3600000).toISOString(),
		createdAt: new Date(Date.now() - 3600000).toISOString(),
		sourceUpdatedAt: new Date(Date.now() - 3600000).toISOString(),
	};
	const request = (
		invitations: unknown[] = [invitation],
		dryRun = true,
		authorized = true,
	) =>
		state.auth.handler(
			new Request(`${origin}${basePath}/project-admin/import-invitations`, {
				method: "POST",
				headers: {
					origin,
					"content-type": "application/json",
					...(authorized
						? { "x-management-fixture": "authorized" }
						: { "allauth-backend-key": "directory-only" }),
				},
				body: JSON.stringify({
					sourceInstance: "stratplan-production",
					dryRun,
					invitations,
				}),
			}),
		);
	return {
		...state,
		context,
		ownerId: owner.user.id,
		organizationId: company.id,
		send,
		invitation,
		request,
	};
}

describe("silent pending invitation migration", () => {
	let state: Awaited<ReturnType<typeof setup>>;
	beforeEach(async () => {
		state = await setup();
	});
	it("requires management authority and dry-runs without native invitations, provenance, mail or events", async () => {
		expect((await state.request(undefined, true, false)).status).toBe(403);
		const before = await state.context.adapter.count({ model: "allauthEvent" });
		const response = await state.request();
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({
			project: "fixture-production",
			dryRun: true,
			created: 0,
			invitations: [
				{
					sourceInvitationId: "local-invite-1",
					status: "would_create",
					invitationId: expect.any(String),
				},
			],
		});
		expect(await state.context.adapter.count({ model: "invitation" })).toBe(0);
		expect(
			await state.context.adapter.count({ model: "allauthInvitationImport" }),
		).toBe(0);
		expect(await state.context.adapter.count({ model: "allauthEvent" })).toBe(
			before,
		);
		expect(state.send).not.toHaveBeenCalled();
	});
	it("preserves recipient, role, inviter, original dates and native acceptance while sending no email", async () => {
		const response = await state.request(undefined, false);
		expect(response.status).toBe(200);
		const result = (await response.json()) as {
			invitations: { invitationId: string }[];
		};
		const invitationId = result.invitations[0].invitationId;
		const native = await state.context.adapter.findOne<{
			email: string;
			role: string;
			expiresAt: Date;
			createdAt: Date;
			inviterId: string;
		}>({ model: "invitation", where: [{ field: "id", value: invitationId }] });
		expect(native).toMatchObject({
			email: state.invitation.email,
			role: "member",
			inviterId: state.ownerId,
		});
		expect(native?.expiresAt.toISOString()).toBe(state.invitation.expiresAt);
		expect(native?.createdAt.toISOString()).toBe(state.invitation.createdAt);
		expect(state.send).not.toHaveBeenCalled();
		expect(JSON.stringify(result)).not.toContain(state.invitation.email);
		const invitee = await state.auth.api.signUpEmail({
			body: {
				email: state.invitation.email,
				name: "Invitee",
				password: "fixture-password",
			},
		});
		await state.context.adapter.update({
			model: "user",
			where: [{ field: "id", value: invitee.user.id }],
			update: { emailVerified: true },
		});
		const login = await state.auth.api.signInEmail({
			body: { email: state.invitation.email, password: "fixture-password" },
			asResponse: true,
		});
		const cookie = login.headers
			.getSetCookie()
			.map((value) => value.split(";", 1)[0])
			.join("; ");
		const accepted = await state.auth.handler(
			new Request(`${origin}${basePath}/organization/accept-invitation`, {
				method: "POST",
				headers: { origin, cookie, "content-type": "application/json" },
				body: JSON.stringify({ invitationId }),
			}),
		);
		expect(accepted.status).toBe(200);
		expect(
			await state.context.adapter.findOne({
				model: "member",
				where: [
					{ field: "organizationId", value: state.organizationId },
					{ field: "userId", value: invitee.user.id },
				],
			}),
		).toMatchObject({ role: "member" });
		expect(await (await state.request(undefined, false)).json()).toMatchObject({
			existing: 1,
			invitations: [
				{ status: "existing", nativeStatus: "accepted", invitationId },
			],
		});
	});
	it("never resets an imported invitation and reports source drift or duplicate destination conflicts", async () => {
		const first = (await (await state.request(undefined, false)).json()) as {
			invitations: { invitationId: string }[];
		};
		expect(
			await (
				await state.request([{ ...state.invitation, role: "admin" }], false)
			).json(),
		).toMatchObject({
			conflicts: 1,
			invitations: [{ reason: "source_changed" }],
		});
		expect(
			await (
				await state.request(
					[{ ...state.invitation, sourceInvitationId: "different-source" }],
					false,
				)
			).json(),
		).toMatchObject({
			conflicts: 1,
			invitations: [{ reason: "invitation_conflict" }],
		});
		expect(await state.context.adapter.count({ model: "invitation" })).toBe(1);
		expect(
			await state.context.adapter.findOne({
				model: "invitation",
				where: [{ field: "id", value: first.invitations[0].invitationId }],
			}),
		).toMatchObject({ role: "member" });
	});
	it.each([
		"unverified",
		"foreign-inviter",
		"no-invite-permission",
		"missing-role",
		"expired",
	])("refuses %s without creating native records", async (reason) => {
		const input = { ...state.invitation };
		if (reason === "unverified")
			await state.context.adapter.update({
				model: "user",
				where: [{ field: "id", value: state.ownerId }],
				update: { emailVerified: false },
			});
		if (reason === "foreign-inviter") input.inviterId = "foreign-user";
		if (reason === "no-invite-permission")
			await state.context.adapter.update({
				model: "member",
				where: [{ field: "userId", value: state.ownerId }],
				update: { role: "member" },
			});
		if (reason === "missing-role") input.role = "missing-role";
		if (reason === "expired")
			input.expiresAt = new Date(Date.now() - 1000).toISOString();
		expect(await (await state.request([input], false)).json()).toMatchObject({
			conflicts: 1,
			invitations: [{ status: "conflict" }],
		});
		expect(await state.context.adapter.count({ model: "invitation" })).toBe(0);
		expect(state.send).not.toHaveBeenCalled();
	});
});

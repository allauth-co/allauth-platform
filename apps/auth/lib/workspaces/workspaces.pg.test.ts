import { randomUUID } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { AuthContext } from "@better-auth/core";
import { runWithEndpointContext } from "@better-auth/core/context";
import { oauthProvider } from "@better-auth/oauth-provider";
import { symmetricEncrypt } from "better-auth/crypto";
import { admin, jwt } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { GET as discovery } from "../../app/.well-known/openid-configuration/route";
import { GET as consoleApplications } from "../../app/api/admin/applications/route";
import { GET as platformWorkspacesGET } from "../../app/api/admin/platform/workspaces/route";
import { POST as projectPOST } from "../../app/api/admin/projects/route";
import { GET as consoleUser } from "../../app/api/admin/users/[userId]/route";
import { GET as consoleUsers } from "../../app/api/admin/users/route";
import { POST as workspacePOST } from "../../app/api/workspaces/route";
import { GET as workspaceSlugGET } from "../../app/api/workspaces/slug/route";
import type { AuthInstance } from "../api";
import { auth } from "../auth";
import { authConfigurationRoute } from "../auth-policy/route";
import type { AuthEnvironment } from "../configuration";
import type { ControlDatabase, ControlPrincipal } from "../control/types";
import {
	getProject,
	listAuthorizedProjects,
	projectRegistryPool,
	provisionProject,
} from "../projects/registry";
import { closeProjectInstances, withProjectAuth } from "../projects/runtime";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import {
	assertWorkspaceAccountDeletion,
	projectAdministrator,
	requireWorkspaceActor,
	requireWorkspacePrincipal,
} from "./authorization";
import {
	createWorkspaceBroker,
	removeUnprovisionedWorkspaceBroker,
	updateProjectBrokerRedirects,
	workspaceBrokerPrivilege,
} from "./broker";
import type { PlatformWorkspaceDirectoryPage } from "./platform-directory";
import {
	acceptWorkspaceInvitation,
	cancelWorkspaceInvitation,
	changeWorkspaceMember,
	createWorkspace,
	deleteWorkspace,
	getWorkspace,
	inviteWorkspaceMember,
	listWorkspaceInvitations,
	listWorkspaces,
	resendWorkspaceInvitation,
	workspaceSlugAvailability,
} from "./repository";
import { platformWorkspaceId, workspaceLimits } from "./types";

const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
describe.skipIf(!existsSync(fixturePath))(
	"real PostgreSQL client console workspaces",
	() => {
		const databaseName = `allauth_workspace_${randomUUID().replaceAll("-", "")}`;
		let administratorPool: Pool;
		let env: AuthEnvironment;
		let database: ControlDatabase;
		let native: Awaited<ReturnType<typeof setupNative>>;
		interface Actor {
			principal: ControlPrincipal;
			headers: Headers;
		}
		let alice: Actor;
		let bob: Actor;
		let carol: Actor;
		let global: Actor;
		let aliceWorkspace: string;
		let bobWorkspace: string;
		let productionSlug: string;
		let routeWorkspaceId: string;
		let rootUsed = false;
		async function setupNative() {
			return getTestInstance(
				{
					baseURL: "http://localhost:3000",
					secret: String(env.BETTER_AUTH_SECRET),
					database: { db: database, type: "postgres", transaction: true },
					logger: { disabled: true },
					emailAndPassword: { enabled: true },
					user: {
						additionalFields: {
							directoryDisabled: { type: "boolean", required: false },
							isAnonymous: { type: "boolean", required: false },
						},
					},
					plugins: [
						admin(),
						jwt(),
						oauthProvider({
							loginPage: "/sign-in",
							consentPage: "/consent",
							scopes: ["openid", "profile", "email"],
							grantTypes: ["authorization_code"],
							clientReference: () => "allauth:platform",
							clientPrivileges: ({ user, session, action }) =>
								workspaceBrokerPrivilege(user, session, action),
						}),
					],
				},
				{ disableTestUser: true },
			);
		}
		async function actor(email: string, role = "user"): Promise<Actor> {
			const result = await native.auth.api.signUpEmail({
				body: {
					email,
					password: "fixture-workspace-password",
					name: email.split("@")[0]!,
				},
			});
			await (await native.auth.$context).adapter.update({
				model: "user",
				where: [{ field: "id", value: result.user.id }],
				update: { emailVerified: true, role },
			});
			const login = await native.auth.api.signInEmail({
				body: { email, password: "fixture-workspace-password" },
				asResponse: true,
			});
			const headers = new Headers({
				cookie: login.headers
					.getSetCookie()
					.map((value) => value.split(";", 1)[0])
					.join("; "),
				origin: "http://localhost:3000",
			});
			const principal = await requireWorkspacePrincipal(headers, env);
			return { principal, headers };
		}
		beforeAll(async () => {
			const fixture: { container: string; DATABASE_URL: string } = JSON.parse(
				readFileSync(fixturePath, "utf8"),
			);
			const url = new URL(fixture.DATABASE_URL);
			if (
				fixture.container !== "allauth-production-test-20261007" ||
				url.hostname !== "127.0.0.1" ||
				url.port !== "55445"
			)
				throw new Error(
					"Only the isolated local AllAuth fixture is permitted.",
				);
			administratorPool = new Pool({
				connectionString: fixture.DATABASE_URL,
				max: 1,
			});
			await administratorPool.query(`CREATE DATABASE "${databaseName}"`);
			url.pathname = `/${databaseName}`;
			env = {
				AUTH_RUNTIME: "node",
				DATABASE_URL: url.toString(),
				BETTER_AUTH_URL: "http://localhost:3000",
				BETTER_AUTH_SECRET: "fixture-workspace-secret-longer-than-thirty-two",
				SCIM_CREDENTIAL_HASH_SECRET:
					"fixture-workspace-scim-secret-longer-than-thirty-two",
				WORKSPACE_MAX_OWNED: "3",
				WORKSPACE_MAX_APPLICATIONS: "1",
				WORKSPACE_MAX_MEMBERS: "5",
				WORKSPACE_MAX_INVITATIONS: "3",
			};
			for (const [key, value] of Object.entries(env))
				vi.stubEnv(key, String(value));
			for (const key of [
				"GOOGLE_CLIENT_ID",
				"GOOGLE_CLIENT_SECRET",
				"GITHUB_CLIENT_ID",
				"GITHUB_CLIENT_SECRET",
				"MICROSOFT_CLIENT_ID",
				"MICROSOFT_CLIENT_SECRET",
				"CLOUDFLARE_ACCOUNT_ID",
				"CLOUDFLARE_EMAIL_API_TOKEN",
				"EMAIL_FROM",
			])
				vi.stubEnv(key, "");
			const pool = projectRegistryPool(env);
			for (const name of readdirSync(
				new URL("../../migrations", import.meta.url),
			)
				.filter((name) => name.endsWith(".sql"))
				.sort())
				await pool.query(
					readFileSync(
						new URL(`../../migrations/${name}`, import.meta.url),
						"utf8",
					),
				);
			database = new Kysely({
				dialect: new PostgresDialect({
					pool: new Pool({
						connectionString: String(env.DATABASE_URL),
						max: 2,
					}),
				}),
			});
			vi.spyOn(process, "cwd").mockReturnValue(
				fileURLToPath(new URL("../..", import.meta.url)),
			);
			native = await setupNative();
			alice = await actor("alice@fixture.example");
			bob = await actor("bob@fixture.example");
			carol = await actor("carol@fixture.example");
			global = await actor("global@fixture.example", "admin");
			vi.stubGlobal(
				"fetch",
				async (input: RequestInfo | URL, init?: RequestInit) => {
					const request =
						input instanceof Request ? input : new Request(input, init);
					const url = new URL(request.url);
					if (url.origin !== String(env.BETTER_AUTH_URL))
						throw new Error("The workspace fixture prohibits external HTTP.");
					return url.pathname === "/.well-known/openid-configuration"
						? discovery(request)
						: native.auth.handler(request);
				},
			);
			aliceWorkspace = (
				await createWorkspace(
					alice.principal,
					{ name: "Alice Workspace", slug: "alice-workspace" },
					env,
				)
			).workspace.id;
			bobWorkspace = (
				await createWorkspace(
					bob.principal,
					{ name: "Bob Workspace", slug: "bob-workspace" },
					env,
				)
			).workspace.id;
		}, 30000);
		afterAll(async () => {
			await closeProjectInstances();
			if (rootUsed) {
				const configured = (await auth.$context).options.database;
				if (configured && typeof configured === "object" && "db" in configured)
					await (configured.db as ControlDatabase).destroy();
			}
			vi.restoreAllMocks();
			if (database) await database.destroy();
			if (env) await projectRegistryPool(env).end();
			if (administratorPool) {
				try {
					await dropClosedFixtureDatabase(administratorPool, databaseName);
				} finally {
					await administratorPool.end();
				}
			}
			vi.unstubAllGlobals();
			vi.unstubAllEnvs();
		});
		it("uses actual verified ordinary root sessions and excludes unrelated/protected workspaces", async () => {
			expect(alice.principal.user.role).toBe("user");
			expect(
				(await listWorkspaces(alice.principal, env)).workspaces.map(
					(row) => row.id,
				),
			).toEqual([aliceWorkspace]);
			expect(
				(await listWorkspaces(global.principal, env)).workspaces.map(
					(row) => row.id,
				),
			).toContain(platformWorkspaceId);
			await expect(
				requireWorkspaceActor(alice.principal, bobWorkspace, env),
			).rejects.toMatchObject({ statusCode: 403 });
			await expect(
				requireWorkspaceActor(alice.principal, platformWorkspaceId, env),
			).rejects.toMatchObject({ statusCode: 403 });
			expect(
				(await getWorkspace(alice.principal, aliceWorkspace, env)).members[0]
					?.userId,
			).toBe(alice.principal.user.id);
		});
		/** @see https://allauth.co/admin/workspaces */
		it("generates unique workspace slugs without requiring a caller-supplied identifier", async () => {
			const first = await createWorkspace(
				global.principal,
				{ name: "Café Studio" },
				env,
			);
			const second = await createWorkspace(
				global.principal,
				{ name: "Café Studio" },
				env,
			);
			expect(first.workspace.slug).toBe("cafe-studio");
			expect(second.workspace.slug).toBe("cafe-studio-2");
			const creators = await Promise.all(
				["slug-one", "slug-two", "slug-three"].map((name) =>
					actor(`${name}@fixture.example`),
				),
			);
			const concurrent = await Promise.all(
				creators.map((creator) =>
					createWorkspace(
						creator.principal,
						{ name: "Concurrent Studio" },
						env,
					),
				),
			);
			expect(
				new Set(concurrent.map((result) => result.workspace.slug)),
			).toEqual(
				new Set([
					"concurrent-studio",
					"concurrent-studio-2",
					"concurrent-studio-3",
				]),
			);
		});
		it("returns a friendly duplicate workspace slug conflict without a partial workspace or membership", async () => {
			await createWorkspace(
				global.principal,
				{ name: "Custom Workspace", slug: "custom-workspace" },
				env,
			);
			await expect(
				createWorkspace(
					global.principal,
					{ name: "Another Workspace", slug: "custom-workspace" },
					env,
				),
			).rejects.toMatchObject({
				statusCode: 409,
				message: "This workspace slug is already in use. Choose another slug.",
			});
			const pool = projectRegistryPool(env);
			expect(
				(
					await pool.query(
						"SELECT id FROM public.\"allauthWorkspace\" WHERE name='Another Workspace'",
					)
				).rows,
			).toHaveLength(0);
			expect(
				(
					await pool.query(
						'SELECT id FROM public."allauthWorkspaceMember" WHERE "workspaceId" NOT IN (SELECT id FROM public."allauthWorkspace")',
					)
				).rows,
			).toHaveLength(0);
		});
		it("checks availability only for current verified creators and reveals no workspace details", async () => {
			expect(
				await workspaceSlugAvailability(alice.principal, "bob-workspace", env),
			).toEqual({
				slug: "bob-workspace",
				available: false,
				suggestion: "bob-workspace-2",
			});
			expect(
				await workspaceSlugAvailability(alice.principal, "unused-studio", env),
			).toEqual({
				slug: "unused-studio",
				available: true,
				suggestion: "unused-studio",
			});
			await expect(
				workspaceSlugAvailability(
					{
						...alice.principal,
						session: { ...alice.principal.session, id: "revoked-session" },
					},
					"bob-workspace",
					env,
				),
			).rejects.toMatchObject({ statusCode: 403 });
			await expect(
				workspaceSlugAvailability(alice.principal, "bob-workspace", {
					...env,
					WORKSPACE_MAX_OWNED: "1",
				}),
			).rejects.toMatchObject({ statusCode: 409 });
			rootUsed = true;
			const request = (query: string, headers: Headers = alice.headers) =>
				new Request(`http://localhost:3000/api/workspaces/slug?${query}`, {
					headers,
				});
			const available = await workspaceSlugGET(request("slug=unused-studio"));
			expect(available.status).toBe(200);
			expect(available.headers.get("cache-control")).toBe("no-store");
			expect(await available.json()).toEqual({
				slug: "unused-studio",
				available: true,
				suggestion: "unused-studio",
			});
			expect(
				(await workspaceSlugGET(request("slug=bob-workspace", new Headers())))
					.status,
			).toBe(401);
			for (const query of [
				"slug=admin",
				"slug=a",
				"slug=first&slug=second",
				"slug=valid-slug&project=tenant",
			])
				expect((await workspaceSlugGET(request(query))).status).toBe(400);
		});
		/** @see https://allauth.co/admin/workspaces?tab=team */
		it("projects a saved platform profile into the same workspace membership even when the caller's principal is stale", async () => {
			const member = await actor("profile-member@fixture.example");
			expect(
				(
					await native.auth.api.updateUser({
						headers: member.headers,
						body: { name: "" },
						asResponse: true,
					})
				).status,
			).toBe(200);
			const workspace = (
				await createWorkspace(
					member.principal,
					{ name: "Profile Workspace", slug: "profile-workspace" },
					env,
				)
			).workspace;
			const before = (await getWorkspace(member.principal, workspace.id, env))
				.members[0]!;
			expect(before).toMatchObject({
				userId: member.principal.user.id,
				name: "",
				email: member.principal.user.email,
			});
			const saved = await native.auth.api.updateUser({
				headers: member.headers,
				body: { name: "Updated workspace member" },
				asResponse: true,
			});
			expect(saved.status).toBe(200);
			expect(await saved.json()).toEqual({ status: true });
			expect(member.principal.user.name).not.toBe("Updated workspace member");
			expect(
				(
					await native.auth.api.getSession({
						headers: member.headers,
						query: { disableCookieCache: true },
					})
				)?.user.name,
			).toBe("Updated workspace member");
			expect(
				(await getWorkspace(member.principal, workspace.id, env)).members,
			).toEqual([{ ...before, name: "Updated workspace member" }]);
			await expect(
				getWorkspace(alice.principal, workspace.id, env),
			).rejects.toMatchObject({ statusCode: 403 });
		});
		/** @see https://allauth.co/admin/workspaces?tab=team */
		it("emails the committed workspace invitation with a distinct acceptance link", async () => {
			const workspace = (
				await createWorkspace(
					global.principal,
					{ name: "Email Workspace", slug: "email-workspace" },
					env,
				)
			).workspace;
			const send = vi.fn(
				async (message: {
					to: string;
					subject: string;
					html: string;
					text: string;
				}) => {
					expect(
						(await getWorkspace(global.principal, workspace.id, env))
							.invitations,
					).toHaveLength(1);
					expect(message).toMatchObject({
						to: "teammate@fixture.example",
						subject: "You're invited to Email Workspace on AllAuth",
					});
					expect(message.text).toContain(
						"http://localhost:3000/accept-workspace-invitation/",
					);
				},
			);
			const result = await inviteWorkspaceMember(
				global.principal,
				workspace.id,
				{ email: "TEAMMATE@fixture.example", role: "admin" },
				{ ...env, EMAIL_FROM: "security@fixture.example", EMAIL: { send } },
			);
			expect(result.delivery.status).toBe("accepted");
			expect(send).toHaveBeenCalledOnce();
			expect(
				(await getWorkspace(global.principal, workspace.id, env)).invitations[0]
					?.emailDelivery,
			).toBe("accepted");
			await expect(
				inviteWorkspaceMember(
					global.principal,
					workspace.id,
					{ email: "teammate@fixture.example" },
					env,
				),
			).rejects.toMatchObject({
				statusCode: 409,
				message:
					"This email already has a pending invitation. Resend it from the team list.",
			});
		});
		/** @see https://allauth.co/admin/workspaces?tab=team */
		it("preserves failed invitations, resends the same link and rechecks permission and expiry", async () => {
			const workspace = (
				await createWorkspace(
					global.principal,
					{ name: "Retry Workspace", slug: "retry-workspace" },
					env,
				)
			).workspace;
			const send = vi
				.fn()
				.mockRejectedValueOnce(new Error("private-provider-response"))
				.mockResolvedValue(undefined);
			const emailEnv = {
				...env,
				EMAIL_FROM: "security@fixture.example",
				EMAIL: { send },
			};
			const created = await inviteWorkspaceMember(
				global.principal,
				workspace.id,
				{ email: "retry@fixture.example" },
				emailEnv,
			);
			expect(created.delivery).toMatchObject({ status: "failed" });
			expect(JSON.stringify(created)).not.toContain(
				"private-provider-response",
			);
			expect(
				(
					await getWorkspace(global.principal, workspace.id, env)
				).invitations.map((row) => row.id),
			).toContain(created.invitation.id);
			expect(
				(await getWorkspace(global.principal, workspace.id, env)).invitations[0]
					?.emailDelivery,
			).toBe("failed");
			await expect(
				resendWorkspaceInvitation(
					bob.principal,
					workspace.id,
					created.invitation.id,
					emailEnv,
				),
			).rejects.toMatchObject({ statusCode: 403 });
			await projectRegistryPool(env).query(
				'UPDATE public."allauthEvent" SET "createdAt"=NOW()-INTERVAL \'61 seconds\' WHERE "targetId"=$1',
				[created.invitation.id],
			);
			const resent = await resendWorkspaceInvitation(
				global.principal,
				workspace.id,
				created.invitation.id,
				emailEnv,
			);
			expect(resent.invitation.id).toBe(created.invitation.id);
			expect(resent.invitation.expiresAt).toEqual(created.invitation.expiresAt);
			expect(resent.delivery.status).toBe("accepted");
			expect(send).toHaveBeenCalledTimes(2);
			expect(send.mock.calls[1]?.[0].text).toContain(
				`/accept-workspace-invitation/${created.invitation.id}`,
			);
			expect(resent.invitation.invitedBy).toBe(created.invitation.invitedBy);
			await expect(
				resendWorkspaceInvitation(
					global.principal,
					workspace.id,
					created.invitation.id,
					emailEnv,
				),
			).rejects.toMatchObject({ statusCode: 429 });
			await projectRegistryPool(env).query(
				'UPDATE public."allauthEvent" SET "createdAt"=NOW()-INTERVAL \'61 seconds\' WHERE "targetId"=$1',
				[created.invitation.id],
			);
			const concurrent = await Promise.allSettled([
				resendWorkspaceInvitation(
					global.principal,
					workspace.id,
					created.invitation.id,
					emailEnv,
				),
				resendWorkspaceInvitation(
					global.principal,
					workspace.id,
					created.invitation.id,
					emailEnv,
				),
			]);
			expect(
				concurrent.filter((attempt) => attempt.status === "fulfilled"),
			).toHaveLength(1);
			expect(
				concurrent.filter((attempt) => attempt.status === "rejected"),
			).toHaveLength(1);
			expect(send).toHaveBeenCalledTimes(3);
			await cancelWorkspaceInvitation(
				global.principal,
				workspace.id,
				created.invitation.id,
				env,
			);
			await expect(
				resendWorkspaceInvitation(
					global.principal,
					workspace.id,
					created.invitation.id,
					emailEnv,
				),
			).rejects.toMatchObject({ statusCode: 404 });
			const expired = await inviteWorkspaceMember(
				global.principal,
				workspace.id,
				{ email: "expired@fixture.example" },
				emailEnv,
			);
			await projectRegistryPool(env).query(
				'UPDATE public."allauthWorkspaceInvitation" SET "expiresAt"=NOW()-INTERVAL \'1 second\' WHERE id=$1',
				[expired.invitation.id],
			);
			await expect(
				resendWorkspaceInvitation(
					global.principal,
					workspace.id,
					expired.invitation.id,
					emailEnv,
				),
			).rejects.toMatchObject({ statusCode: 404 });
		});
		/** @see https://allauth.co/admin/workspaces?tab=team */
		it("preserves the original inviter when a platform administrator resends and denies revoked senders", async () => {
			const workspace = (
				await createWorkspace(
					global.principal,
					{ name: "Sender Workspace", slug: "sender-workspace" },
					env,
				)
			).workspace;
			const send = vi.fn(async (_message: { text: string }) => undefined);
			const emailEnv = {
				...env,
				EMAIL_FROM: "security@fixture.example",
				EMAIL: { send },
			};
			const seat = await inviteWorkspaceMember(
				global.principal,
				workspace.id,
				{ email: alice.principal.user.email, role: "admin" },
				emailEnv,
			);
			await acceptWorkspaceInvitation(alice.principal, seat.invitation.id, env);
			const ownerInvite = await inviteWorkspaceMember(
				global.principal,
				workspace.id,
				{ email: "owner@fixture.example", role: "owner" },
				emailEnv,
			);
			await expect(
				resendWorkspaceInvitation(
					alice.principal,
					workspace.id,
					ownerInvite.invitation.id,
					emailEnv,
				),
			).rejects.toMatchObject({ statusCode: 403 });
			const created = await inviteWorkspaceMember(
				alice.principal,
				workspace.id,
				{ email: "original@fixture.example" },
				emailEnv,
			);
			await projectRegistryPool(env).query(
				'UPDATE public."allauthEvent" SET "createdAt"=NOW()-INTERVAL \'61 seconds\' WHERE "targetId"=$1',
				[created.invitation.id],
			);
			const resent = await resendWorkspaceInvitation(
				global.principal,
				workspace.id,
				created.invitation.id,
				emailEnv,
			);
			expect(resent.invitation.invitedBy).toBe(alice.principal.user.id);
			expect(send.mock.calls.at(-1)?.[0].text).toContain(
				alice.principal.user.email,
			);
			await projectRegistryPool(env).query(
				'UPDATE public."user" SET banned=true WHERE id=$1',
				[alice.principal.user.id],
			);
			try {
				await expect(
					resendWorkspaceInvitation(
						global.principal,
						workspace.id,
						created.invitation.id,
						emailEnv,
					),
				).rejects.toMatchObject({
					statusCode: 403,
					message:
						"This invitation's sender no longer has permission. Cancel it and create a new invitation.",
				});
			} finally {
				await projectRegistryPool(env).query(
					'UPDATE public."user" SET banned=false WHERE id=$1',
					[alice.principal.user.id],
				);
			}
		});
		it("binds invitations to the current verified email, handles expiry and rejects replay", async () => {
			const invitation = (
				await inviteWorkspaceMember(
					alice.principal,
					aliceWorkspace,
					{ email: "CAROL@fixture.example", role: "member" },
					env,
				)
			).invitation;
			expect(
				(await listWorkspaceInvitations(carol.principal, env)).invitations.map(
					(row) => row.id,
				),
			).toContain(invitation.id);
			await expect(
				acceptWorkspaceInvitation(bob.principal, invitation.id, env),
			).rejects.toMatchObject({ statusCode: 404 });
			await acceptWorkspaceInvitation(carol.principal, invitation.id, env);
			await expect(
				acceptWorkspaceInvitation(carol.principal, invitation.id, env),
			).rejects.toMatchObject({ statusCode: 404 });
			const summary = await getWorkspace(carol.principal, aliceWorkspace, env);
			expect(summary.permissions.manage).toBe(false);
			expect(summary.members).toEqual([]);
			await expect(
				requireWorkspaceActor(carol.principal, aliceWorkspace, env),
			).rejects.toMatchObject({ statusCode: 403 });
			expect(await listAuthorizedProjects(carol.principal, env)).toEqual([]);
			const expiring = (
				await inviteWorkspaceMember(
					alice.principal,
					aliceWorkspace,
					{ email: "bob@fixture.example", role: "admin" },
					env,
				)
			).invitation;
			await projectRegistryPool(env).query(
				'UPDATE public."allauthWorkspaceInvitation" SET "expiresAt"=NOW()-INTERVAL \'1 second\' WHERE id=$1',
				[expiring.id],
			);
			await expect(
				acceptWorkspaceInvitation(bob.principal, expiring.id, env),
			).rejects.toMatchObject({ statusCode: 404 });
		});
		it("retains the last owner and prevents administrators elevating themselves or accepting revoked invites", async () => {
			const ownerSeat = (
				await getWorkspace(alice.principal, aliceWorkspace, env)
			).members.find((member) => member.userId === alice.principal.user.id)!;
			await expect(
				changeWorkspaceMember(
					alice.principal,
					aliceWorkspace,
					ownerSeat.id,
					undefined,
					env,
				),
			).rejects.toMatchObject({ statusCode: 409 });
			const carolSeat = (
				await getWorkspace(alice.principal, aliceWorkspace, env)
			).members.find((member) => member.userId === carol.principal.user.id)!;
			await changeWorkspaceMember(
				alice.principal,
				aliceWorkspace,
				carolSeat.id,
				{ role: "admin" },
				env,
			);
			await expect(
				changeWorkspaceMember(
					carol.principal,
					aliceWorkspace,
					carolSeat.id,
					{ role: "owner" },
					env,
				),
			).rejects.toMatchObject({ statusCode: 403 });
			const invitation = (
				await inviteWorkspaceMember(
					carol.principal,
					aliceWorkspace,
					{ email: "bob@fixture.example", role: "member" },
					env,
				)
			).invitation;
			await changeWorkspaceMember(
				alice.principal,
				aliceWorkspace,
				carolSeat.id,
				{ role: "member" },
				env,
			);
			await expect(
				acceptWorkspaceInvitation(bob.principal, invitation.id, env),
			).rejects.toMatchObject({ statusCode: 404 });
		});
		it("enforces ownership quotas concurrently and publishes bounded configured limits", async () => {
			const attempts = await Promise.allSettled(
				Array.from({ length: 4 }, (_, index) =>
					createWorkspace(
						bob.principal,
						{
							name: `Quota Workspace ${index}`,
							slug: `quota-workspace-${index}`,
						},
						env,
					),
				),
			);
			expect(
				attempts.filter((result) => result.status === "fulfilled"),
			).toHaveLength(2);
			expect(
				attempts.filter((result) => result.status === "rejected"),
			).toHaveLength(2);
			expect(
				workspaceLimits({
					...env,
					WORKSPACE_MAX_OWNED: "100000",
					WORKSPACE_MAX_APPLICATIONS: "-1",
				}),
			).toMatchObject({
				ownedWorkspaces: 3,
				applicationsPerWorkspace: 5,
				environmentsPerApplication: 2,
			});
		});
		it.each([
			{ emailVerified: false },
			{ banned: true },
			{ directoryDisabled: true },
			{ isAnonymous: true },
		])("revokes workspace management from stored user state despite a prior principal: %j", async (update) => {
			const context = await native.auth.$context;
			await context.adapter.update({
				model: "user",
				where: [{ field: "id", value: alice.principal.user.id }],
				update,
			});
			await expect(
				requireWorkspaceActor(alice.principal, aliceWorkspace, env),
			).rejects.toMatchObject({ statusCode: 403 });
			await context.adapter.update({
				model: "user",
				where: [{ field: "id", value: alice.principal.user.id }],
				update: {
					emailVerified: true,
					banned: false,
					directoryDisabled: false,
					isAnonymous: false,
				},
			});
		});
		it("rejects impersonated/expired stored sessions and never trusts a tenant role or bearer", async () => {
			const pool = projectRegistryPool(env);
			await pool.query(
				'UPDATE public.session SET "impersonatedBy"=$1 WHERE id=$2',
				[global.principal.user.id, alice.principal.session.id],
			);
			await expect(
				requireWorkspaceActor(alice.principal, aliceWorkspace, env),
			).rejects.toMatchObject({ statusCode: 403 });
			await pool.query(
				'UPDATE public.session SET "impersonatedBy"=NULL,"expiresAt"=NOW()-INTERVAL \'1 second\' WHERE id=$1',
				[alice.principal.session.id],
			);
			await expect(
				requireWorkspaceActor(alice.principal, aliceWorkspace, env),
			).rejects.toMatchObject({ statusCode: 403 });
			await pool.query(
				"UPDATE public.session SET \"expiresAt\"=NOW()+INTERVAL '1 day' WHERE id=$1",
				[alice.principal.session.id],
			);
			await expect(
				requireWorkspacePrincipal(
					new Headers({
						...Object.fromEntries(alice.headers),
						authorization: "Bearer forged",
					}),
					env,
				),
			).rejects.toMatchObject({ statusCode: 403 });
			expect(
				await projectAdministrator(
					{ workspaceId: bobWorkspace },
					{
						...alice.principal,
						user: { ...alice.principal.user, role: "admin" },
					},
					env,
				),
			).toBeNull();
		});
		it("creates only a fixed native broker inside private authorization context and cleans it without leaking privileges", async () => {
			const instance = native.auth as unknown as AuthInstance;
			const arbitrary = {
				client_name: "Arbitrary",
				redirect_uris: ["https://attacker.example/callback"],
				scope: "openid",
			};
			await expect(
				native.auth.api.adminCreateOAuthClient({
					headers: alice.headers,
					body: arbitrary,
				}),
			).rejects.toMatchObject({ statusCode: 401 });
			const input = {
				name: "Alice Fixture App",
				slug: "alice-fixture-app",
				primaryOrigin: "https://alice-app.fixture.example",
				origins: [],
				environment: "production" as const,
			};
			const [broker, rejected] = await Promise.all([
				createWorkspaceBroker(
					instance,
					alice.headers,
					alice.principal,
					aliceWorkspace,
					input,
					env,
				),
				native.auth.api
					.createOAuthClient({ headers: bob.headers, body: arbitrary })
					.then(
						() => false,
						() => true,
					),
			]);
			expect(rejected).toBe(true);
			expect(
				workspaceBrokerPrivilege(
					alice.principal.user,
					alice.principal.session,
					"create",
				),
			).toBe(false);
			const saved = (await native.auth.$context).adapter;
			const client = await saved.findOne<Record<string, unknown>>({
				model: "oauthClient",
				where: [{ field: "clientId", value: broker.clientId }],
			});
			expect(client).toMatchObject({
				scopes: ["openid", "profile", "email"],
				grantTypes: ["authorization_code"],
				requirePKCE: true,
				skipConsent: false,
			});
			expect(client?.redirectUris).toEqual([
				`${input.primaryOrigin}/api/allauth/callback/allauth`,
				"https://alice-fixture-app-accounts.allauth.co/api/auth/callback/allauth",
				"https://alice-fixture-app-api.allauth.co/api/auth/callback/allauth",
			]);
			expect(client?.clientSecret).not.toBe(broker.clientSecret);
			await expect(
				removeUnprovisionedWorkspaceBroker(
					instance,
					alice.headers,
					alice.principal,
					{ ...broker },
				),
			).rejects.toMatchObject({ statusCode: 403 });
			await removeUnprovisionedWorkspaceBroker(
				instance,
				alice.headers,
				alice.principal,
				broker,
			);
			expect(
				await saved.findOne({
					model: "oauthClient",
					where: [{ field: "clientId", value: broker.clientId }],
				}),
			).toBeNull();
			await expect(
				native.auth.api.adminCreateOAuthClient({
					headers: alice.headers,
					body: arbitrary,
				}),
			).rejects.toMatchObject({ statusCode: 401 });
		});
		it("isolates application groups and development/production data while bounding schema provisioning", async () => {
			const credentials = {
				clientId: "fixture-broker",
				clientSecret: "fixture-broker-secret",
			};
			const first = await provisionProject(
				{
					name: "Alice Production",
					slug: "alice-production",
					primaryOrigin: "https://alice.fixture.example",
					origins: [],
					environment: "production",
				},
				credentials,
				alice.principal.user.id,
				env,
				{ workspaceId: aliceWorkspace, principal: alice.principal },
			);
			productionSlug = first.slug;
			const development = await provisionProject(
				{
					name: "Alice Development",
					slug: "alice-development",
					primaryOrigin: "http://localhost:4321",
					origins: [],
					environment: "development",
					applicationId: first.applicationId,
				},
				credentials,
				alice.principal.user.id,
				env,
				{ workspaceId: aliceWorkspace, principal: alice.principal },
			);
			expect(first.schemaName).not.toBe(development.schemaName);
			expect(first.applicationId).toBe(development.applicationId);
			await expect(
				provisionProject(
					{
						name: "Duplicate development",
						slug: "duplicate-development",
						primaryOrigin: "http://localhost:5321",
						origins: [],
						applicationId: first.applicationId,
						environment: "development",
					},
					credentials,
					alice.principal.user.id,
					env,
					{ workspaceId: aliceWorkspace, principal: alice.principal },
				),
			).rejects.toMatchObject({
				statusCode: 409,
				message: "This application already has a development environment.",
			});
			expect(
				(await listAuthorizedProjects(alice.principal, env)).map(
					(row) => row.id,
				),
			).toEqual([first.id, development.id]);
			expect(await listAuthorizedProjects(bob.principal, env)).toEqual([]);
			await expect(
				provisionProject(
					{
						name: "Cross Workspace",
						slug: "cross-workspace",
						primaryOrigin: "https://cross.fixture.example",
						origins: [],
						applicationId: first.applicationId,
						environment: "development",
					},
					credentials,
					bob.principal.user.id,
					env,
					{ workspaceId: bobWorkspace, principal: bob.principal },
				),
			).rejects.toMatchObject({ statusCode: 404 });
			await expect(
				provisionProject(
					{
						name: "Over Quota",
						slug: "over-quota",
						primaryOrigin: "https://over.fixture.example",
						origins: [],
					},
					credentials,
					alice.principal.user.id,
					env,
					{ workspaceId: aliceWorkspace, principal: alice.principal },
				),
			).rejects.toMatchObject({ statusCode: 409 });
			expect(
				(
					await projectRegistryPool(env).query(
						"SELECT id FROM public.\"allauthProject\" WHERE slug IN ('cross-workspace','over-quota')",
					)
				).rows,
			).toHaveLength(0);
			expect(
				(await listAuthorizedProjects(global.principal, env)).map(
					(row) => row.id,
				),
			).toContain(first.id);
			expect(await projectAdministrator(first, alice.principal, env)).toEqual(
				alice.principal,
			);
			expect(await projectAdministrator(first, bob.principal, env)).toBeNull();
			await expect(
				deleteWorkspace(alice.principal, aliceWorkspace, env),
			).rejects.toMatchObject({ statusCode: 409 });
		}, 30000);
		it("requires an explicit workspace for ordinary and global application creation", async () => {
			rootUsed = true;
			const pool = projectRegistryPool(env);
			const before = Number(
				(
					await pool.query<{ total: string }>(
						'SELECT COUNT(*)::text AS total FROM public."oauthClient"',
					)
				).rows[0]!.total,
			);
			for (const actor of [alice, global]) {
				const request = new Request(
					"http://localhost:3000/api/admin/projects",
					{
						method: "POST",
						headers: {
							...Object.fromEntries(actor.headers),
							"content-type": "application/json",
						},
						body: JSON.stringify({
							name: "Unscoped application",
							slug: `unscoped-${actor.principal.user.id.slice(0, 8).toLowerCase()}`,
							primaryOrigin: "https://unscoped.fixture.example",
							origins: [],
							environment: "production",
						}),
					},
				);
				const response = await projectPOST(request);
				expect(response.status).toBe(400);
				expect(await response.json()).toMatchObject({
					error: "Choose a workspace for this application.",
				});
			}
			expect(
				Number(
					(
						await pool.query<{ total: string }>(
							'SELECT COUNT(*)::text AS total FROM public."oauthClient"',
						)
					).rows[0]!.total,
				),
			).toBe(before);
			expect(
				(
					await pool.query(
						'SELECT id FROM public."allauthProject" WHERE "primaryOrigin"=\'https://unscoped.fixture.example\'',
					)
				).rows,
			).toHaveLength(0);
		}, 30000);
		it("refuses implicit or mismatched workspace authority before provisioning a namespace", async () => {
			const input = {
				name: "Unscoped registry app",
				slug: "unscoped-registry-app",
				primaryOrigin: "https://registry.fixture.example",
				origins: [],
			};
			const broker = {
				clientId: "fixture-broker",
				clientSecret: "fixture-broker-secret",
			};
			// @ts-expect-error Untyped callers must not bypass mandatory workspace authority.
			const unscoped = provisionProject(
				input,
				broker,
				global.principal.user.id,
				env,
			);
			await expect(unscoped).rejects.toMatchObject({ statusCode: 400 });
			await expect(
				provisionProject(
					{ ...input, workspaceId: bobWorkspace },
					broker,
					alice.principal.user.id,
					env,
					{ workspaceId: aliceWorkspace, principal: alice.principal },
				),
			).rejects.toMatchObject({ statusCode: 400 });
			await expect(
				provisionProject(input, broker, alice.principal.user.id, env, {
					workspaceId: bobWorkspace,
					principal: alice.principal,
				}),
			).rejects.toMatchObject({ statusCode: 403 });
			await expect(
				createWorkspaceBroker(
					native.auth as unknown as AuthInstance,
					alice.headers,
					alice.principal,
					aliceWorkspace,
					{ ...input, workspaceId: bobWorkspace },
					env,
				),
			).rejects.toMatchObject({ statusCode: 400 });
			expect(
				(
					await projectRegistryPool(env).query(
						"SELECT id FROM public.\"allauthProject\" WHERE slug='unscoped-registry-app'",
					)
				).rows,
			).toHaveLength(0);
		});
		it("creates a workspace through the actual client route and requires same-origin bounded input", async () => {
			rootUsed = true;
			const request = (origin = "http://localhost:3000") =>
				new Request("http://localhost:3000/api/workspaces", {
					method: "POST",
					headers: {
						...Object.fromEntries(alice.headers),
						origin,
						"content-type": "application/json",
					},
					body: JSON.stringify({
						name: "Actual Route Workspace",
						slug: "actual-route-workspace",
					}),
				});
			expect(
				(await workspacePOST(request("https://foreign.example"))).status,
			).toBe(403);
			const response = await workspacePOST(request());
			expect(response.status).toBe(201);
			expect(response.headers.get("cache-control")).toBe("no-store");
			const value = (await response.json()) as { workspace: { id: string } };
			expect(value).toMatchObject({
				workspace: { role: "owner", name: "Actual Route Workspace" },
				limits: { ownedWorkspaces: 3 },
			});
			routeWorkspaceId = value.workspace.id;
		});
		it("provisions through the actual ordinary client app route and cleans native broker credentials when quota rejects", async () => {
			const request = (slug: string, workspaceId = routeWorkspaceId) =>
				new Request("http://localhost:3000/api/admin/projects", {
					method: "POST",
					headers: {
						...Object.fromEntries(alice.headers),
						"content-type": "application/json",
					},
					body: JSON.stringify({
						name: "Actual Client App",
						slug,
						workspaceId,
						primaryOrigin: "https://actual-app.fixture.example",
						origins: [],
						environment: "production",
					}),
				});
			expect(
				(await projectPOST(request("foreign-client-app", bobWorkspace))).status,
			).toBe(403);
			const response = await projectPOST(request("actual-client-app"));
			expect(response.status).toBe(201);
			const value = (await response.json()) as {
				project: { id: string; workspaceId: string };
				proxySecret: string;
			};
			expect(value.project.workspaceId).toBe(routeWorkspaceId);
			expect(value.proxySecret).toMatch(/^[a-f0-9]{64}$/);
			const pool = projectRegistryPool(env);
			const before = Number(
				(
					await pool.query<{ total: string }>(
						'SELECT COUNT(*)::text AS total FROM public."oauthClient"',
					)
				).rows[0]!.total,
			);
			expect((await projectPOST(request("over-quota-client-app"))).status).toBe(
				409,
			);
			expect(
				Number(
					(
						await pool.query<{ total: string }>(
							'SELECT COUNT(*)::text AS total FROM public."oauthClient"',
						)
					).rows[0]!.total,
				),
			).toBe(before);
			expect(
				(
					await pool.query(
						"SELECT id FROM public.\"allauthProject\" WHERE slug='over-quota-client-app'",
					)
				).rows,
			).toHaveLength(0);
		}, 30000);
		it("lists registered platform applications only for a live platform administrator", async () => {
			const clientId = `fixture-${randomUUID()}`;
			const database = projectRegistryPool(env);
			await database.query(
				`INSERT INTO public."oauthClient"(id,"clientId","clientSecret","referenceId","redirectUris",name,metadata)
				 VALUES ($1,$1,'fixture-stored-secret','allauth:platform','[]','Console fixture','{"allauthAllowLocalhost":true}')`,
				[clientId],
			);
			const read = (headers: Headers) =>
				consoleApplications(
					new Request(`${env.BETTER_AUTH_URL}/api/admin/applications`, {
						headers,
					}),
				);
			expect((await read(alice.headers)).status).toBe(403);
			const result = await read(global.headers);
			expect(result.status).toBe(200);
			const body = await result.text();
			expect(JSON.parse(body)).toMatchObject({
				applications: expect.arrayContaining([
					expect.objectContaining({
						client_id: clientId,
						client_name: "Console fixture",
						allowLocalhost: true,
					}),
				]),
			});
			expect(body).not.toContain("fixture-stored-secret");
		});

		it("uses the parent's actual scoped native console guards for owners and rejects foreign/root/revoked authority", async () => {
			rootUsed = true;
			await withProjectAuth(
				productionSlug,
				async (instance) => {
					const context = await instance.$context;
					await runWithEndpointContext(
						{
							context: context as unknown as AuthContext,
							path: "/local-fixture-seed",
							headers: alice.headers,
						},
						() =>
							context.internalAdapter.createUser(
								{
									name: "Actual tenant user",
									email: "tenant@fixture.example",
									emailVerified: true,
								},
								{ method: "admin" },
							),
					);
					const overview = await instance.api.controlOverview({
						headers: alice.headers,
					});
					expect(overview.totals.users).toBe(1);
					await expect(
						instance.api.controlOverview({ headers: bob.headers }),
					).rejects.toMatchObject({ statusCode: 403 });
				},
				env,
			);
			const request = (headers: Headers, path: string) =>
				new Request(`${env.BETTER_AUTH_URL}${path}`, { headers });
			const users = await consoleUsers(
				request(alice.headers, `/api/admin/users?project=${productionSlug}`),
			);
			expect(users.status).toBe(200);
			expect(await users.json()).toMatchObject({
				users: [expect.objectContaining({ email: "tenant@fixture.example" })],
				total: 1,
			});
			expect(
				(
					await consoleUsers(
						request(bob.headers, `/api/admin/users?project=${productionSlug}`),
					)
				).status,
			).toBeGreaterThanOrEqual(400);
			expect(
				(await consoleUsers(request(alice.headers, "/api/admin/users"))).status,
			).toBe(403);
			expect(
				(
					await authConfigurationRoute(
						request(
							alice.headers,
							`/api/admin/configuration?project=${productionSlug}`,
						),
					)
				).status,
			).toBe(200);
			expect(
				(
					await authConfigurationRoute(
						request(
							bob.headers,
							`/api/admin/configuration?project=${productionSlug}`,
						),
					)
				).status,
			).toBeGreaterThanOrEqual(400);
			expect(
				(
					await authConfigurationRoute(
						request(alice.headers, "/api/admin/configuration"),
					)
				).status,
			).toBe(403);
			const seat = (
				await getWorkspace(alice.principal, aliceWorkspace, env)
			).members.find((member) => member.userId === carol.principal.user.id)!;
			await changeWorkspaceMember(
				alice.principal,
				aliceWorkspace,
				seat.id,
				{ role: "admin" },
				env,
			);
			expect(
				(
					await consoleUsers(
						request(
							carol.headers,
							`/api/admin/users?project=${productionSlug}`,
						),
					)
				).status,
			).toBe(200);
			await changeWorkspaceMember(
				alice.principal,
				aliceWorkspace,
				seat.id,
				{ role: "member" },
				env,
			);
			expect(
				(
					await consoleUsers(
						request(
							carol.headers,
							`/api/admin/users?project=${productionSlug}`,
						),
					)
				).status,
			).toBeGreaterThanOrEqual(400);
			await withProjectAuth(
				productionSlug,
				async (instance) => {
					await expect(
						instance.api.controlOverview({ headers: carol.headers }),
					).rejects.toMatchObject({ statusCode: 403 });
				},
				env,
			);
		}, 30000);
		it("requires native account ownership transfer and the database also prevents direct orphaning", async () => {
			await expect(
				assertWorkspaceAccountDeletion(alice.principal.user.id, env),
			).rejects.toMatchObject({ statusCode: 409 });
			await expect(
				projectRegistryPool(env).query(
					'DELETE FROM public."user" WHERE id=$1',
					[alice.principal.user.id],
				),
			).rejects.toMatchObject({ code: "23514" });
			expect(
				(await getWorkspace(alice.principal, aliceWorkspace, env)).members.some(
					(member) =>
						member.userId === alice.principal.user.id &&
						member.role === "owner",
				),
			).toBe(true);
			await expect(
				assertWorkspaceAccountDeletion(carol.principal.user.id, env),
			).resolves.toBeUndefined();
		});
		/** @see ../projects/management-plugin.ts (trusted selected workspace authority contract) */
		it("permits actual workspace owners in native project administration and denies revoked membership or tenant-only admin", async () => {
			await withProjectAuth(
				productionSlug,
				async (instance) => {
					const nativeRequest = (actor: Actor, path: string, body?: unknown) =>
						instance.handler(
							new Request(
								`${env.BETTER_AUTH_URL}/api/projects/${productionSlug}/auth${path}`,
								{
									method: body === undefined ? "GET" : "POST",
									headers: {
										...Object.fromEntries(actor.headers),
										...(body === undefined
											? {}
											: { "content-type": "application/json" }),
									},
									...(body === undefined ? {} : { body: JSON.stringify(body) }),
								},
							),
						);
					expect(alice.principal.user.role).toBe("user");
					const listed = await nativeRequest(
						alice,
						"/project-admin/list-users",
					);
					expect(listed.status).toBe(200);
					expect(listed.headers.get("cache-control")).toBe("no-store");
					const created = await nativeRequest(
						alice,
						"/project-admin/create-user",
						{
							name: "Workspace managed user",
							email: "workspace-managed@fixture.example",
						},
					);
					expect(created.status).toBe(200);
					expect(await created.json()).toMatchObject({
						user: {
							email: "workspace-managed@fixture.example",
							emailVerified: false,
							role: "user",
						},
					});
					expect(
						(await nativeRequest(bob, "/project-admin/list-users")).status,
					).toBe(403);
					const seat = (
						await getWorkspace(alice.principal, aliceWorkspace, env)
					).members.find(
						(member) => member.userId === carol.principal.user.id,
					)!;
					await changeWorkspaceMember(
						alice.principal,
						aliceWorkspace,
						seat.id,
						{ role: "admin" },
						env,
					);
					expect(
						(await nativeRequest(carol, "/project-admin/list-users")).status,
					).toBe(200);
					await changeWorkspaceMember(
						alice.principal,
						aliceWorkspace,
						seat.id,
						{ role: "member" },
						env,
					);
					expect(
						(await nativeRequest(carol, "/project-admin/list-users")).status,
					).toBe(403);
					const context = await instance.$context;
					const tenantAdmin = await runWithEndpointContext(
						{
							context: context as unknown as AuthContext,
							path: "/local-fixture-seed",
							headers: alice.headers,
						},
						() =>
							context.internalAdapter.createUser(
								{
									name: "Tenant administrator",
									email: "tenant-admin@fixture.example",
									emailVerified: true,
									role: "admin",
								},
								{ method: "admin" },
							),
					);
					const passwordHash = await runWithEndpointContext(
						{
							context: context as unknown as AuthContext,
							path: "/local-fixture-seed",
							headers: alice.headers,
						},
						() => context.password.hash("fixture-tenant-admin-password"),
					);
					await context.internalAdapter.linkAccount({
						providerId: "credential",
						accountId: tenantAdmin.id,
						userId: tenantAdmin.id,
						password: passwordHash,
					});
					const login = await instance.api.signInEmail({
						body: {
							email: tenantAdmin.email,
							password: "fixture-tenant-admin-password",
						},
						headers: new Headers({
							origin: "http://localhost:3000",
							"x-real-ip": "192.0.2.91",
						}),
						asResponse: true,
					});
					expect(login.status).toBe(200);
					const tenantHeaders = new Headers({
						cookie: login.headers
							.getSetCookie()
							.map((value) => value.split(";", 1)[0])
							.join("; "),
						origin: "http://localhost:3000",
					});
					const tenant = await instance.api.getSession({
						headers: tenantHeaders,
					});
					expect(tenant?.user.role).toBe("admin");
					expect(
						(
							await nativeRequest(
								{ headers: tenantHeaders, principal: alice.principal },
								"/project-admin/list-users",
							)
						).status,
					).toBe(403);
				},
				env,
			);
		}, 30000);
		it("serializes direct concurrent owner removals so one owner always survives", async () => {
			const workspace = (
				await createWorkspace(
					alice.principal,
					{ name: "Concurrent Owner Guard", slug: "concurrent-owner-guard" },
					env,
				)
			).workspace;
			const invite = (
				await inviteWorkspaceMember(
					alice.principal,
					workspace.id,
					{ email: carol.principal.user.email, role: "owner" },
					env,
				)
			).invitation;
			await acceptWorkspaceInvitation(carol.principal, invite.id, env);
			const pool = new Pool({
				connectionString: String(env.DATABASE_URL),
				max: 2,
			});
			const first = await pool.connect();
			const second = await pool.connect();
			try {
				await first.query("BEGIN");
				await second.query("BEGIN");
				await first.query(
					'DELETE FROM public."allauthWorkspaceMember" WHERE "workspaceId"=$1 AND "userId"=$2',
					[workspace.id, alice.principal.user.id],
				);
				await second.query(
					'DELETE FROM public."allauthWorkspaceMember" WHERE "workspaceId"=$1 AND "userId"=$2',
					[workspace.id, carol.principal.user.id],
				);
				const results = await Promise.allSettled([
					first.query("COMMIT"),
					second.query("COMMIT"),
				]);
				expect(
					results.filter((result) => result.status === "fulfilled"),
				).toHaveLength(1);
				expect(
					results.filter((result) => result.status === "rejected"),
				).toHaveLength(1);
				expect(
					(
						await projectRegistryPool(env).query(
							'SELECT id FROM public."allauthWorkspaceMember" WHERE "workspaceId"=$1 AND role=\'owner\'',
							[workspace.id],
						)
					).rows,
				).toHaveLength(1);
			} finally {
				await first.query("ROLLBACK");
				await second.query("ROLLBACK");
				first.release();
				second.release();
				await pool.end();
			}
		});
		it("updates only stored broker callbacks for fully active domains and denies arbitrary native client updates", async () => {
			const pool = projectRegistryPool(env);
			const project = await getProject(productionSlug, env);
			const instance = native.auth as unknown as AuthInstance;
			const broker = await createWorkspaceBroker(
				instance,
				alice.headers,
				alice.principal,
				aliceWorkspace,
				{
					name: project.name,
					slug: project.slug,
					primaryOrigin: project.primaryOrigin,
					origins: [],
				},
				env,
			);
			await pool.query(
				'UPDATE public."allauthProject" SET "brokerClientId"=$1,"brokerSecret"=$2 WHERE id=$3',
				[
					broker.clientId,
					await symmetricEncrypt({
						key: String(env.BETTER_AUTH_SECRET),
						data: broker.clientSecret,
					}),
					project.id,
				],
			);
			const activePair = randomUUID();
			const pendingPair = randomUUID();
			await pool.query(
				'INSERT INTO public."allauthDomainPair" (id,"projectId",domain,"createdBy") VALUES ($1,$2,\'fixturecustomer.net\',$3),($4,$2,\'pendingcustomer.net\',$3)',
				[activePair, project.id, alice.principal.user.id, pendingPair],
			);
			for (const kind of ["accounts", "frontend-api"])
				await pool.query(
					'INSERT INTO public."allauthCustomHostname" (id,"pairId","projectId",kind,hostname,"proofToken","ownershipVerifiedAt","providerStatus","sslStatus","routingVerifiedAt") VALUES ($1,$2,$3,$4,$5,\'fixture-proof\',NOW(),\'active\',\'active\',NOW()),($6,$7,$3,$4,$8,\'fixture-proof\',NULL,\'pending\',\'pending\',NULL)',
					[
						randomUUID(),
						activePair,
						project.id,
						kind,
						`${kind}.fixturecustomer.net`,
						randomUUID(),
						pendingPair,
						`${kind}.pendingcustomer.net`,
					],
				);
			const configured = {
				...env,
				CLOUDFLARE_SAAS_ZONE_ID: "0".repeat(32),
				CLOUDFLARE_SAAS_API_TOKEN: "fixture-provider-token-never-sent",
				CLOUDFLARE_SAAS_CNAME_TARGET: "saas.allauth.co",
				CLOUDFLARE_SAAS_READY: "true",
			};
			const storedMetadata = {
				unrelatedSentinel: "preserved",
				allauthOrganizationIds: ["fixture-organization"],
				allauthResourceURI: "https://resource.fixture.example",
			};
			const adapter = (await native.auth.$context).adapter;
			await adapter.update({
				model: "oauthClient",
				where: [{ field: "clientId", value: broker.clientId }],
				update: { metadata: storedMetadata },
			});
			await expect(
				native.auth.api.adminUpdateOAuthClient({
					headers: alice.headers,
					body: {
						client_id: broker.clientId,
						update: { redirect_uris: ["https://attacker.example/callback"] },
					},
				}),
			).rejects.toMatchObject({ statusCode: 401 });
			await expect(
				updateProjectBrokerRedirects(
					instance,
					alice.headers,
					alice.principal,
					project,
					["https://accounts.pendingcustomer.net"],
					configured,
				),
			).rejects.toMatchObject({ statusCode: 403 });
			await expect(
				updateProjectBrokerRedirects(
					instance,
					bob.headers,
					bob.principal,
					project,
					[],
					configured,
				),
			).rejects.toMatchObject({ statusCode: 403 });
			await expect(
				updateProjectBrokerRedirects(
					instance,
					alice.headers,
					alice.principal,
					project,
					["https://attacker.example"],
					configured,
				),
			).rejects.toMatchObject({ statusCode: 403 });
			await updateProjectBrokerRedirects(
				instance,
				alice.headers,
				alice.principal,
				project,
				["https://accounts.fixturecustomer.net"],
				configured,
			);
			const retained = await adapter.findOne<{ metadata: unknown }>({
				model: "oauthClient",
				where: [{ field: "clientId", value: broker.clientId }],
			});
			expect(
				typeof retained?.metadata === "string"
					? JSON.parse(retained.metadata)
					: retained?.metadata,
			).toMatchObject({
				...storedMetadata,
				allauthProjectBroker: project.slug,
				allauthWorkspaceId: aliceWorkspace,
				allauthAllowLocalhost: false,
			});
			const read = () =>
				adapter.findOne<{ redirectUris: string[] }>({
					model: "oauthClient",
					where: [{ field: "clientId", value: broker.clientId }],
				});
			expect((await read())?.redirectUris).toEqual([
				`${project.primaryOrigin}/api/allauth/callback/allauth`,
				`https://${project.slug}-accounts.allauth.co/api/auth/callback/allauth`,
				`https://${project.slug}-api.allauth.co/api/auth/callback/allauth`,
				"https://accounts.fixturecustomer.net/api/auth/callback/allauth",
				"https://frontend-api.fixturecustomer.net/api/auth/callback/allauth",
			]);
			await pool.query(
				'UPDATE public."allauthDomainPair" SET deleting=true WHERE id=$1',
				[activePair],
			);
			await updateProjectBrokerRedirects(
				instance,
				alice.headers,
				alice.principal,
				project,
				[],
				configured,
			);
			expect(
				(await read())?.redirectUris.some((uri) =>
					uri.includes("fixturecustomer.net"),
				),
			).toBe(false);
			expect(
				workspaceBrokerPrivilege(
					alice.principal.user,
					alice.principal.session,
					"update",
				),
			).toBe(false);
			await expect(
				native.auth.api.updateOAuthClient({
					headers: alice.headers,
					body: {
						client_id: broker.clientId,
						update: { redirect_uris: ["https://attacker.example/callback"] },
					},
				}),
			).rejects.toMatchObject({ statusCode: 401 });
		});
		it("rolls back workspace membership and legacy audit when the immutable event write fails", async () => {
			const pool = projectRegistryPool(env);
			await pool.query(
				"CREATE FUNCTION public.fixture_reject_workspace_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.type='workspace.created' THEN RAISE EXCEPTION 'fixture rejected audit'; END IF; RETURN NEW; END; $$",
			);
			await pool.query(
				'CREATE TRIGGER fixture_reject_workspace_audit BEFORE INSERT ON public."allauthEvent" FOR EACH ROW EXECUTE FUNCTION public.fixture_reject_workspace_audit()',
			);
			try {
				await expect(
					createWorkspace(
						global.principal,
						{ name: "Rejected Workspace", slug: "rejected-workspace" },
						env,
					),
				).rejects.toThrow("fixture rejected audit");
				expect(
					(
						await pool.query(
							"SELECT id FROM public.\"allauthWorkspace\" WHERE slug='rejected-workspace'",
						)
					).rows,
				).toHaveLength(0);
			} finally {
				await pool.query(
					'DROP TRIGGER fixture_reject_workspace_audit ON public."allauthEvent"',
				);
				await pool.query(
					"DROP FUNCTION public.fixture_reject_workspace_audit()",
				);
			}
		});

		describe("platform workspace directory", () => {
			const firstWorkspace = "directory-fixture-001";
			const fixtureSearch = "Directory fixture";
			const createdAt = "2025-03-04T01:02:03.000Z";
			let secondaryOwner: Actor;
			let tenantId: string;
			let tenantHeaders: Headers;
			beforeAll(async () => {
				secondaryOwner = await actor("directory-second-owner@fixture.example");
				const pool = projectRegistryPool(env);
				await pool.query(
					`
				INSERT INTO public."allauthWorkspace" (id, name, slug, "createdAt")
				SELECT 'directory-fixture-' || number, 'Directory fixture ' || number || suffix,
					'directory-fixture-' || number, $1
				FROM generate_series(1, 106) AS n
				CROSS JOIN LATERAL (SELECT lpad(n::text, 3, '0') AS number,
					CASE WHEN n=106 THEN ' !%_' ELSE '' END AS suffix) AS label
			`,
					[createdAt],
				);
				await pool.query(
					`
				INSERT INTO public."allauthWorkspaceMember" (id, "workspaceId", "userId", role)
				SELECT 'seat-' || id, id, $1, 'owner' FROM public."allauthWorkspace" WHERE slug LIKE 'directory-fixture-%'
			`,
					[global.principal.user.id],
				);
				await pool.query(
					`
				INSERT INTO public."allauthWorkspaceMember" (id, "workspaceId", "userId", role) VALUES
					('directory-owner-seat', $1, $2, 'owner'),
					('directory-secondary-owner-seat', $1, $3, 'owner'),
					('directory-member-seat', $1, $4, 'member'),
					('directory-admin-seat', 'directory-fixture-002', $2, 'admin'),
					('directory-later-member-seat', 'directory-fixture-003', $2, 'member');
			`,
					[
						firstWorkspace,
						alice.principal.user.id,
						secondaryOwner.principal.user.id,
						carol.principal.user.id,
					],
				);
				await pool.query(
					`INSERT INTO public.organization (id,name,slug,"createdAt") VALUES ($1,'Native organization','directory-native-org',now())`,
					[firstWorkspace],
				);
				await pool.query(
					`INSERT INTO public.member (id,"organizationId","userId",role,"createdAt") VALUES ('directory-native-owner',$1,$2,'owner',now())`,
					[firstWorkspace, bob.principal.user.id],
				);
				await pool.query(
					`INSERT INTO public."allauthWorkspaceInvitation" (id,"workspaceId",email,role,"expiresAt") VALUES ('directory-pending-owner',$1,'directory-pending-owner@fixture.example','owner',now()+interval '1 day')`,
					[firstWorkspace],
				);
				const credentials = {
					clientId: "fixture-directory-broker",
					clientSecret: "fixture-directory-broker-secret",
				};
				const scope = {
					workspaceId: firstWorkspace,
					principal: global.principal,
				};
				const provision = (
					slug: string,
					environment: "development" | "production",
					applicationId?: string,
				) =>
					provisionProject(
						{
							name: slug,
							slug,
							primaryOrigin: `https://${slug}.fixture.example`,
							origins: [],
							environment,
							applicationId,
						},
						credentials,
						global.principal.user.id,
						env,
						scope,
					);
				const production = await provision(
					"directory-fixture-production",
					"production",
				);
				await provision(
					"directory-fixture-development",
					"development",
					production.applicationId,
				);
				await provision("directory-fixture-other", "production");
				await withProjectAuth(
					production.slug,
					async (instance) => {
						const context = await instance.$context;
						const password = "fixture-directory-tenant-password";
						const tenant = await runWithEndpointContext(
							{
								context: context as unknown as AuthContext,
								path: "/local-fixture-seed",
								headers: alice.headers,
							},
							() =>
								context.internalAdapter.createUser(
									{
										name: "Tenant shadow owner",
										email: alice.principal.user.email,
										emailVerified: true,
										role: "admin",
									},
									{ method: "admin" },
								),
						);
						const passwordHash = await runWithEndpointContext(
							{
								context: context as unknown as AuthContext,
								path: "/local-fixture-seed",
								headers: alice.headers,
							},
							() => context.password.hash(password),
						);
						await context.internalAdapter.linkAccount({
							providerId: "credential",
							accountId: tenant.id,
							userId: tenant.id,
							password: passwordHash,
						});
						const login = await instance.api.signInEmail({
							body: { email: tenant.email, password },
							headers: new Headers({
								origin: "http://localhost:3000",
								"x-real-ip": "192.0.2.92",
							}),
							asResponse: true,
						});
						expect(login.status).toBe(200);
						tenantHeaders = new Headers({
							cookie: login.headers
								.getSetCookie()
								.map((value) => value.split(";", 1)[0])
								.join("; "),
						});
						expect(
							(await instance.api.getSession({ headers: tenantHeaders }))?.user
								.role,
						).toBe("admin");
						tenantId = tenant.id;
					},
					env,
				);
			}, 30000);
			const request = (
				query = new URLSearchParams(),
				headers = global.headers,
			) => {
				rootUsed = true;
				return platformWorkspacesGET(
					new Request(
						`http://localhost:3000/api/admin/platform/workspaces?${query}`,
						{ headers },
					),
				);
			};
			async function page(
				query: Record<string, string>,
			): Promise<PlatformWorkspaceDirectoryPage> {
				const response = await request(new URLSearchParams(query));
				expect(response.status).toBe(200);
				expect(response.headers.get("cache-control")).toBe("no-store");
				return response.json();
			}

			it("paginates all matches in stable order and searches beyond the selector limit", async () => {
				const first = await page({ search: fixtureSearch, limit: "100" });
				expect(first).toMatchObject({ total: 106, offset: 0, limit: 100 });
				expect(first.workspaces).toHaveLength(100);
				expect(first.workspaces.at(-1)?.id).toBe("directory-fixture-100");
				const second = await page({ search: fixtureSearch, offset: "100" });
				expect(second).toMatchObject({ total: 106, offset: 100, limit: 25 });
				expect(second.workspaces.map((row) => row.id)).toEqual(
					Array.from(
						{ length: 6 },
						(_, index) => `directory-fixture-${101 + index}`,
					),
				);
				expect(await page({ search: fixtureSearch, offset: "106" })).toEqual({
					total: 106,
					offset: 106,
					limit: 25,
					workspaces: [],
				});
				for (const search of ["!%_", "%", "_", "DIRECTORY-FIXTURE-106"]) {
					expect(
						(await page({ search })).workspaces.map((row) => row.id),
					).toEqual(["directory-fixture-106"]);
				}
				expect((await page({ search: "' OR 1=1 --" })).total).toBe(0);
			});

			it("projects root owners and counts, and filters exact stored memberships across roles", async () => {
				const { workspaces } = await page({
					search: secondaryOwner.principal.user.email.toUpperCase(),
				});
				expect(workspaces).toEqual([
					{
						id: firstWorkspace,
						name: "Directory fixture 001",
						slug: firstWorkspace,
						createdAt,
						protected: false,
						owners: [alice, secondaryOwner, global].map(
							({
								principal: {
									user: { id, name, email },
								},
							}) => ({ id, name, email }),
						),
						memberCount: 4,
						applicationCount: 2,
						environmentCount: 3,
						membershipRole: null,
					},
				]);
				expect(
					(
						await page({ search: secondaryOwner.principal.user.name })
					).workspaces.map((row) => row.id),
				).toEqual([firstWorkspace]);
				expect(
					(await page({ search: "directory-pending-owner@fixture.example" }))
						.total,
				).toBe(0);
				expect((await page({ search: "Tenant shadow owner" })).total).toBe(0);
				expect(
					(
						await page({
							search: fixtureSearch,
							accountId: alice.principal.user.id,
						})
					).workspaces.map(({ id, membershipRole }) => [id, membershipRole]),
				).toEqual([
					[firstWorkspace, "owner"],
					["directory-fixture-002", "admin"],
					["directory-fixture-003", "member"],
				]);
				for (const accountId of [
					alice.principal.user.email,
					bob.principal.user.id,
					tenantId,
				]) {
					expect((await page({ search: fixtureSearch, accountId })).total).toBe(
						0,
					);
				}
				expect(
					(await page({ search: "AllAuth platform" })).workspaces,
				).toMatchObject([
					{
						id: platformWorkspaceId,
						protected: true,
						owners: [],
						memberCount: 0,
						membershipRole: null,
					},
				]);
			});

			it("requires fresh root platform authority for workspace and account reads", async () => {
				const unattached = await actor("directory-unattached@fixture.example");
				const userId = unattached.principal.user.id;
				const accountList = (headers: Headers) =>
					consoleUsers(
						new Request(
							`http://localhost:3000/api/admin/users?${new URLSearchParams({ search: userId })}`,
							{ headers },
						),
					);
				const accountDetail = (headers: Headers) =>
					consoleUser(
						new Request(
							`http://localhost:3000/api/admin/users/${encodeURIComponent(userId)}`,
							{ headers },
						),
						{ params: Promise.resolve({ userId }) },
					);
				const statusCodes = async (headers: Headers) =>
					(
						await Promise.all([
							request(new URLSearchParams(), headers),
							accountList(headers),
							accountDetail(headers),
						])
					).map((response) => response.status);
				const accounts = await accountList(global.headers);
				const account = await accountDetail(global.headers);
				expect(accounts.status).toBe(200);
				expect(account.status).toBe(200);
				expect(await accounts.json()).toMatchObject({
					total: 1,
					users: [{ id: userId }],
				});
				expect(await account.json()).toMatchObject({ user: { id: userId } });
				expect(await page({ accountId: userId })).toEqual({
					workspaces: [],
					total: 0,
					offset: 0,
					limit: 25,
				});
				expect(await statusCodes(new Headers())).toEqual([401, 401, 401]);
				expect(await statusCodes(tenantHeaders)).toEqual([401, 401, 401]);
				for (const scoped of [alice, carol, secondaryOwner]) {
					expect(await statusCodes(scoped.headers)).toEqual([403, 403, 403]);
				}
				const bearer = new Headers(global.headers);
				bearer.set("authorization", "Bearer local-fixture-token");
				expect(await statusCodes(bearer)).toEqual([403, 403, 403]);
				const pool = projectRegistryPool(env);
				try {
					await pool.query(
						"UPDATE public.\"user\" SET role='user' WHERE id=$1",
						[global.principal.user.id],
					);
					expect(await statusCodes(global.headers)).toEqual([403, 403, 403]);
					await pool.query(
						'UPDATE public."user" SET role=\'admin\',"directoryDisabled"=true WHERE id=$1',
						[global.principal.user.id],
					);
					expect(await statusCodes(global.headers)).toEqual([403, 403, 403]);
					await pool.query(
						'UPDATE public."user" SET "directoryDisabled"=false WHERE id=$1',
						[global.principal.user.id],
					);
					await pool.query(
						'UPDATE public.session SET "impersonatedBy"=$1 WHERE id=$2',
						[alice.principal.user.id, global.principal.session.id],
					);
					expect(await statusCodes(global.headers)).toEqual([403, 403, 403]);
				} finally {
					await pool.query(
						'UPDATE public."user" SET role=\'admin\',"directoryDisabled"=false WHERE id=$1',
						[global.principal.user.id],
					);
					await pool.query(
						'UPDATE public.session SET "impersonatedBy"=NULL WHERE id=$1',
						[global.principal.session.id],
					);
				}
			});

			it("rejects malformed or scoped workspace directory queries", async () => {
				for (const query of [
					"project=",
					"project=tenant",
					"project=&project=tenant",
					"workspace=",
					"workspaceId=",
					"search=&search=",
					"accountId=",
					"limit=",
					"limit=101",
					"offset=-1",
					"offset=1e2",
					"search=%00",
					"unknown=1",
				]) {
					expect(
						(await request(new URLSearchParams(query))).status,
						query,
					).toBe(400);
				}
			});
		});
	},
);

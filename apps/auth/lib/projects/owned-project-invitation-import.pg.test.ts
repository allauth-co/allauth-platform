import { randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { runWithAdapter } from "@better-auth/core/context";
import { APIError } from "better-auth";
import { admin, organization } from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { defaultAuthPolicy } from "../auth-policy/policy";
import { clerkCompatiblePasswords } from "../clerk-password";
import { allauthControl } from "../control";
import type { ControlPrincipal } from "../control/types";
import { dropClosedFixtureDatabase } from "../testing/postgres-fixture";
import { invitationImportPath } from "./invitation-import-contract";
import { projectManagement } from "./management-plugin";
import { createOwnedProjectEngine } from "./owned-project-engine";

const fixture = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const origin = "https://invitation-import.fixture.example";
const password = "Disposable-invitation-import-7!";
const platformSecret = "disposable-invitation-import-platform-secret";
const root = "fixture-workspace-owner";
const inviter = "fixture-import-inviter";
const disabledInviter = "fixture-disabled-inviter";
const organizationId = "fixture-import-org";
const sourceInstance = "source-invitation-fixture";
const nativeRecipient = "fixture-native-recipient";
const ownedRecipient = "fixture-owned-recipient";
const migrations = [
	"001-initial-auth",
	"002-control-plane",
	"005-free-plugins",
	"016-invitation-import-provenance",
];
const email = (id: string) => `${id}@invitation-import.fixture.example`;

function realm(slug: string, workspaceId = randomUUID()) {
	const id = randomUUID();
	return {
		id,
		slug,
		workspaceId,
		schemaName: `allauth_project_${id.replaceAll("-", "")}`,
		basePath: `/api/projects/${slug}/auth`,
		secret: `disposable-invitation-import-project-secret-${id}`,
	};
}

const alpha = realm("fixture-invitation-import");
const beta = realm(
	"fixture-invitation-control",
	"00000000-0000-4000-8000-000000000001",
);

function request(path: string, body: object, cookies = "", caller = origin) {
	return new Request(`${origin}${path}`, {
		method: "POST",
		headers: {
			origin: caller,
			"content-type": "application/json",
			"user-agent": "invitation-import-fixture",
			...(cookies ? { cookie: cookies } : {}),
		},
		body: JSON.stringify(body),
	});
}

function sessionCookie(response: Response) {
	return response.headers
		.getSetCookie()
		.map((value) => value.split(";", 1)[0])
		.join("; ");
}

function fixtureRow(sourceInvitationId: string, recipient: string) {
	return {
		sourceInvitationId,
		organizationId,
		email: recipient,
		role: "member",
		inviterId: inviter,
		createdAt: "2025-01-01T01:00:00.000+01:00",
		sourceUpdatedAt: "2025-01-02T01:00:00.000+01:00",
		expiresAt: new Date(Date.now() + 2 * 86_400_000).toISOString(),
	};
}

async function native(
	pool: Pool,
	options: {
		basePath: string;
		secret: string;
		project?: typeof alpha;
		readRoot?: (headers: Headers) => Promise<ControlPrincipal | null>;
		send?: () => Promise<void>;
	},
) {
	const db = new Kysely<Record<string, Record<string, unknown>>>({
		dialect: new PostgresDialect({ pool }),
	});
	const { auth } = await getTestInstance(
		{
			baseURL: origin,
			basePath: options.basePath,
			secret: options.secret,
			logger: { disabled: true },
			database: { db, type: "postgres", transaction: true },
			advanced: {
				cookiePrefix: options.project
					? `allauth_project_${options.project.slug}`
					: "better-auth",
			},
			emailAndPassword: { enabled: true, password: clerkCompatiblePasswords },
			user: {
				additionalFields: {
					directoryDisabled: { type: "boolean", required: false },
				},
			},
			plugins: [
				admin(),
				allauthControl(),
				...(options.project
					? [
							organization({
								dynamicAccessControl: { enabled: true },
								requireEmailVerificationOnInvitation: true,
								sendInvitationEmail: options.send,
							}),
							projectManagement({
								projectId: options.project.id,
								projectSlug: options.project.slug,
								baseURL: origin,
								async requirePlatformAdmin(ctx) {
									const actor = await options.readRoot?.(
										ctx.headers ?? new Headers(),
									);
									if (!actor) throw new APIError("FORBIDDEN");
									return actor;
								},
							}),
						]
					: []),
			],
		},
		{ disableTestUser: true },
	);
	return auth;
}

describe.skipIf(!existsSync(fixture))(
	"isolated invitation import across project engines",
	() => {
		const name = `allauth_hosted_${randomUUID().replaceAll("-", "")}`;
		const pools: Pool[] = [];
		const sendNativeMail = vi.fn(async () => {});
		const sendOwnedMail = vi.fn(async () => {});
		let administrator: Pool;
		let database: Pool;
		let platform: Awaited<ReturnType<typeof native>>;
		let legacy: Awaited<ReturnType<typeof native>>;
		let owned: ReturnType<typeof createOwnedProjectEngine>;
		let control: ReturnType<typeof createOwnedProjectEngine>;
		let rootCookies: string;
		let created = false;

		async function readRoot(
			headers: Headers,
		): Promise<ControlPrincipal | null> {
			const value = await runWithAdapter(
				(await platform.$context).adapter,
				() =>
					platform.api.getSession({
						headers,
						query: { disableCookieCache: true },
					}),
			);
			if (!value) return null;
			return {
				user: {
					...value.user,
					role: value.user.role ?? undefined,
					banned: value.user.banned ?? undefined,
				},
				session: {
					id: value.session.id,
					userId: value.session.userId,
					impersonatedBy: value.session.impersonatedBy ?? undefined,
				},
			};
		}

		beforeAll(async () => {
			const config = JSON.parse(readFileSync(fixture, "utf8")) as {
				container: string;
				DATABASE_URL: string;
			};
			const url = new URL(config.DATABASE_URL);
			if (
				config.container !== "allauth-production-test-20261007" ||
				url.hostname !== "127.0.0.1" ||
				url.port !== "55445"
			)
				throw new Error(
					"Invitation import requires isolated fixture PostgreSQL.",
				);
			administrator = new Pool({ connectionString: url.href, max: 1 });
			await administrator.query(`CREATE DATABASE "${name}"`);
			created = true;
			url.pathname = `/${name}`;
			database = new Pool({ connectionString: url.href, max: 5 });
			pools.push(database);
			const migrate = (migration: string) =>
				readFileSync(
					new URL(`../../migrations/${migration}.sql`, import.meta.url),
					"utf8",
				);
			const client = await database.connect();
			try {
				for (const migration of [
					...migrations,
					"003-projects",
					"008-application-environments",
					"009-workspaces",
				])
					await client.query(migrate(migration));
				for (const project of [alpha, beta]) {
					await client.query(`CREATE SCHEMA "${project.schemaName}"`);
					await client.query(`SET search_path TO "${project.schemaName}"`);
					for (const migration of migrations)
						await client.query(migrate(migration));
				}
				await client.query("SET search_path TO public");
			} finally {
				client.release();
			}
			const passwordHash = await clerkCompatiblePasswords.hash(password);
			async function addUser(schema: string, id: string, disabled = false) {
				await database.query(
					`INSERT INTO "${schema}"."user" (id,name,email,"emailVerified",role,"directoryDisabled")
				 VALUES ($1,$1,$2,true,'user',$3)`,
					[id, email(id), disabled],
				);
				await database.query(
					`INSERT INTO "${schema}"."account" (id,"accountId","providerId","userId",password,"updatedAt")
				 VALUES ($1,$2,'credential',$2,$3,now())`,
					[randomUUID(), id, passwordHash],
				);
			}
			await addUser("public", root);
			await database.query(
				`INSERT INTO public."allauthWorkspace" (id,name,slug,"createdBy") VALUES ($1,'Fixture workspace','invitation-import-workspace',$2)`,
				[alpha.workspaceId, root],
			);
			await database.query(
				`INSERT INTO public."allauthWorkspaceMember" (id,"workspaceId","userId",role) VALUES ($1,$2,$3,'owner')`,
				[randomUUID(), alpha.workspaceId, root],
			);
			for (const project of [alpha, beta])
				await database.query(
					`INSERT INTO public."allauthProject" (id,name,slug,"schemaName","primaryOrigin","brokerClientId","brokerSecret","proxyVersion","createdBy","applicationId",environment,"workspaceId")
				 VALUES ($1,$2,$2,$3,$4,'fixture','fixture','1',$5,$1,'development',$6)`,
					[
						project.id,
						project.slug,
						project.schemaName,
						origin,
						root,
						project.workspaceId,
					],
				);
			for (const id of [
				inviter,
				disabledInviter,
				nativeRecipient,
				ownedRecipient,
			])
				await addUser(alpha.schemaName, id, id === disabledInviter);
			await database.query(
				`INSERT INTO "${alpha.schemaName}"."organization" (id,name,slug,"createdAt") VALUES ($1,'Fixture org',$1,now())`,
				[organizationId],
			);
			await database.query(
				`INSERT INTO "${alpha.schemaName}"."organizationRole" (id,"organizationId",role,permission)
			 VALUES ($1,$2,'invite-special','{"invitation":["create"]}')`,
				[randomUUID(), organizationId],
			);
			for (const [id, role] of [
				[inviter, "member, invite-special"],
				[disabledInviter, "owner"],
			])
				await database.query(
					`INSERT INTO "${alpha.schemaName}"."member" (id,"organizationId","userId",role,"createdAt")
				 VALUES ($1,$2,$3,$4,now())`,
					[randomUUID(), organizationId, id, role],
				);
			const rootPool = new Pool({
				connectionString: url.href,
				max: 2,
				options: "-c search_path=public",
			});
			const projectPool = new Pool({
				connectionString: url.href,
				max: 3,
				options: `-c search_path=${alpha.schemaName}`,
			});
			pools.push(rootPool, projectPool);
			platform = await native(rootPool, {
				basePath: "/api/auth",
				secret: platformSecret,
			});
			legacy = await native(projectPool, {
				...alpha,
				project: alpha,
				readRoot,
				send: sendNativeMail,
			});
			const signed = await platform.handler(
				request("/api/auth/sign-in/email", { email: email(root), password }),
			);
			expect(signed.status).toBe(200);
			rootCookies = sessionCookie(signed);
			expect(
				await readRoot(new Headers({ cookie: rootCookies })),
			).not.toBeNull();
			const create = (project: typeof alpha) =>
				createOwnedProjectEngine({
					database,
					project,
					baseURL: origin,
					basePath: project.basePath,
					signingSecret: project.secret,
					policy: defaultAuthPolicy,
					trustedOrigins: [],
					trustedIP: () => "192.0.2.46",
					organization: { invitationEmail: { send: sendOwnedMail } },
					adminDeletion: {
						id: project.id,
						workspaceId: project.workspaceId,
						platformOrigin: origin,
						readWorkspacePrincipal: readRoot,
					},
				});
			owned = create(alpha);
			control = create(beta);
		});

		afterAll(async () => {
			try {
				await Promise.all(pools.map((pool) => pool.end()));
				if (created) await dropClosedFixtureDatabase(administrator, name);
			} finally {
				await administrator?.end();
			}
		});

		const body = (invitations: object[], dryRun?: boolean) => ({
			sourceInstance,
			invitations,
			dryRun,
		});
		const send = (
			engine: "native" | "owned",
			input: object,
			cookies = rootCookies,
			caller = origin,
		) => {
			const incoming = request(
				alpha.basePath + invitationImportPath,
				input,
				cookies,
				caller,
			);
			return engine === "native"
				? legacy.handler(incoming)
				: owned.dispatch(incoming);
		};
		async function response(engine: "native" | "owned", input: object) {
			const result = await send(engine, input);
			expect(result.status).toBe(200);
			expect(result.headers.get("cache-control")).toBe("no-store");
			return (await result.json()) as {
				invitations: Array<{
					invitationId?: string;
					status: string;
					nativeStatus?: string;
					reason?: string;
				}>;
			};
		}

		it("preserves native dry runs, exact source fingerprints and acceptance in both engine directions", async () => {
			const first = fixtureRow(
				"native-import",
				email(nativeRecipient).toUpperCase(),
			);
			const second = {
				...fixtureRow("owned-import", email(ownedRecipient)),
				role: "invite-special",
			};
			const preview = await response("owned", body([second]));
			expect(preview).toMatchObject({
				project: alpha.slug,
				projectId: alpha.id,
				dryRun: true,
				created: 0,
				invitations: [{ status: "would_create" }],
			});
			expect(await response("native", body([second]))).toEqual(preview);
			expect(
				(
					await database.query(
						`SELECT 1 FROM "${alpha.schemaName}"."invitation"`,
					)
				).rowCount,
			).toBe(0);
			expect(
				(
					await database.query(
						`SELECT 1 FROM "${alpha.schemaName}"."allauthInvitationImport"`,
					)
				).rowCount,
			).toBe(0);
			expect(
				(
					await database.query(
						`SELECT 1 FROM "${alpha.schemaName}"."allauthEvent" WHERE type='admin.invitation-import'`,
					)
				).rowCount,
			).toBe(0);
			expect((await send("owned", body([second]), "")).status).toBe(403);
			expect(
				(
					await send(
						"owned",
						body([second]),
						rootCookies,
						"https://other.fixture.example",
					)
				).status,
			).toBe(403);
			expect(
				(
					await control.dispatch(
						request(
							beta.basePath + invitationImportPath,
							body([second]),
							rootCookies,
						),
					)
				).status,
			).toBe(403);

			const nativeImport = await response("native", body([first], false));
			expect(nativeImport).toMatchObject({
				created: 1,
				invitations: [{ status: "created", nativeStatus: "pending" }],
			});
			const candidateImport = await response("owned", body([second], false));
			expect(candidateImport).toMatchObject({
				created: 1,
				invitations: [
					{
						invitationId: preview.invitations[0].invitationId,
						sourceUpdatedAt: "2025-01-02T00:00:00.000Z",
						status: "created",
						nativeStatus: "pending",
					},
				],
			});
			expect(JSON.stringify(candidateImport)).not.toContain(second.email);
			const importedId = nativeImport.invitations[0].invitationId!;
			const candidateId = candidateImport.invitations[0].invitationId!;
			const rows = await database.query(
				`SELECT i.id,i.email,i.role,i."inviterId",i."createdAt",i."expiresAt",p."sourceInstance",p."sourceInvitationId",p.fingerprint
			 FROM "${alpha.schemaName}"."invitation" i JOIN "${alpha.schemaName}"."allauthInvitationImport" p ON p."invitationId"=i.id`,
			);
			expect(rows.rows).toEqual(
				expect.arrayContaining([
					expect.objectContaining({
						id: importedId,
						email: first.email.toLowerCase(),
						inviterId: inviter,
						sourceInstance,
					}),
					expect.objectContaining({
						id: candidateId,
						email: second.email,
						role: second.role,
						inviterId: inviter,
						createdAt: new Date(second.createdAt),
						expiresAt: new Date(second.expiresAt),
						sourceInstance,
						sourceInvitationId: second.sourceInvitationId,
						fingerprint: expect.stringMatching(/^[a-f0-9]{64}$/),
					}),
				]),
			);
			expect(await response("owned", body([first], false))).toMatchObject({
				existing: 1,
				invitations: [{ invitationId: importedId, nativeStatus: "pending" }],
			});
			expect(await response("native", body([second], false))).toMatchObject({
				existing: 1,
				invitations: [{ invitationId: candidateId, nativeStatus: "pending" }],
			});
			expect(
				await response("owned", body([{ ...first, role: "admin" }])),
			).toMatchObject({
				conflicts: 1,
				invitations: [{ reason: "source_changed" }],
			});
			const ownedSignIn = await owned.dispatch(
				request(`${alpha.basePath}/sign-in/email`, {
					email: email(nativeRecipient),
					password,
				}),
			);
			expect(ownedSignIn.status).toBe(200);
			const ownedAcceptance = await owned.dispatch(
				request(
					`${alpha.basePath}/organization/accept-invitation`,
					{ invitationId: importedId },
					sessionCookie(ownedSignIn),
				),
			);
			expect(ownedAcceptance.status).toBe(200);
			const nativeSignIn = await legacy.handler(
				request(`${alpha.basePath}/sign-in/email`, {
					email: email(ownedRecipient),
					password,
				}),
			);
			expect(nativeSignIn.status).toBe(200);
			const nativeAcceptance = await legacy.handler(
				request(
					`${alpha.basePath}/organization/accept-invitation`,
					{ invitationId: candidateId },
					sessionCookie(nativeSignIn),
				),
			);
			expect(nativeAcceptance.status).toBe(200);
			expect(await response("owned", body([first]))).toMatchObject({
				existing: 1,
				invitations: [{ nativeStatus: "accepted" }],
			});
			expect(await response("native", body([second]))).toMatchObject({
				existing: 1,
				invitations: [{ nativeStatus: "accepted" }],
			});
			const audits = await database.query(
				`SELECT "actorId","organizationId","targetId","userAgent",metadata FROM "${alpha.schemaName}"."allauthEvent" WHERE type='admin.invitation-import'`,
			);
			expect(audits.rows).toHaveLength(2);
			expect(audits.rows).toEqual(
				expect.arrayContaining(
					[importedId, candidateId].map((targetId) => ({
						actorId: root,
						organizationId,
						targetId,
						userAgent: "invitation-import-fixture",
						metadata: { signal: "invitation-import", version: 1 },
					})),
				),
			);
			expect(sendNativeMail).not.toHaveBeenCalled();
			expect(sendOwnedMail).not.toHaveBeenCalled();
			await database.query(
				`DELETE FROM "${alpha.schemaName}"."invitation" WHERE id=$1`,
				[candidateId],
			);
			for (const engine of ["native", "owned"] as const)
				expect(await response(engine, body([second]))).toMatchObject({
					conflicts: 1,
					invitations: [{ reason: "source_conflict" }],
				});
		});

		it("serializes pending rows, retains exact conflict outcomes, and rolls back an audit failure", async () => {
			const destination = "pending@invitation-import.fixture.example";
			const duplicate = [
				fixtureRow("different-source-a", destination),
				fixtureRow("different-source-b", destination),
			];
			const conflicts = body([
				{
					...fixtureRow("expired", destination),
					expiresAt: "2024-01-01T00:00:00.000Z",
				},
				{
					...fixtureRow("wrong-org", destination),
					organizationId: "unknown-organization",
				},
				{ ...fixtureRow("wrong-role", destination), role: "missing-role" },
				{ ...fixtureRow("disabled", destination), inviterId: disabledInviter },
				fixtureRow("member", email(inviter)),
				...duplicate,
			]);
			const checked = await response("owned", conflicts);
			expect(checked).toEqual(await response("native", conflicts));
			expect(checked.invitations.map(({ reason }) => reason)).toEqual([
				"expired",
				"organization_missing",
				"role_missing",
				"invalid_inviter",
				"membership_conflict",
				undefined,
				"invitation_conflict",
			]);
			const concurrent = await Promise.all(
				duplicate.map((row) => response("owned", body([row], false))),
			);
			expect(
				concurrent.map(({ invitations }) => invitations[0].status).sort(),
			).toEqual(["conflict", "created"]);
			expect(
				concurrent.find(
					({ invitations }) => invitations[0].status === "conflict",
				)?.invitations[0].reason,
			).toBe("invitation_conflict");
			const audit = `"${alpha.schemaName}"."allauthEvent"`;
			await database.query(
				`ALTER TABLE ${audit} ADD CONSTRAINT fixture_invite_audit_failure CHECK (type <> 'admin.invitation-import') NOT VALID`,
			);
			const atomic = fixtureRow(
				"atomic-audit",
				"atomic@invitation-import.fixture.example",
			);
			try {
				expect(await response("owned", body([atomic], false))).toMatchObject({
					conflicts: 1,
					invitations: [{ reason: "write_conflict" }],
				});
				expect(
					(
						await database.query(
							`SELECT 1 FROM "${alpha.schemaName}"."invitation" WHERE email=$1`,
							[atomic.email],
						)
					).rowCount,
				).toBe(0);
				expect(
					(
						await database.query(
							`SELECT 1 FROM "${alpha.schemaName}"."allauthInvitationImport" WHERE "sourceInvitationId"=$1`,
							[atomic.sourceInvitationId],
						)
					).rowCount,
				).toBe(0);
			} finally {
				await database.query(
					`ALTER TABLE ${audit} DROP CONSTRAINT fixture_invite_audit_failure`,
				);
			}
			expect(sendNativeMail).not.toHaveBeenCalled();
			expect(sendOwnedMail).not.toHaveBeenCalled();
		});
	},
);

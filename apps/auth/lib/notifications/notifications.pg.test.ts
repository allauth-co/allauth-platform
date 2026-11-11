import { randomUUID } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { AuthEnvironment } from "../configuration";
import type { ControlPrincipal } from "../control/types";
import { deliverReleaseNotifications } from "./delivery";
import { platformReleases, sdkReleases } from "./releases";
import {
	listNotifications,
	markNotificationsRead,
	recordSdkVersionObservation,
	setNotificationPreferences,
} from "./repository";

const fixturePath = new URL(
	"../../../../.secrets/local-postgres.json",
	import.meta.url,
);
const releaseId = sdkReleases[0].id;
const existingAccountAt = new Date(
	Date.parse(sdkReleases[0].publishedAt) - 86400_000,
);
const principal = (id: string): ControlPrincipal => ({
	user: { id, name: id, email: `${id}@fixture.example`, emailVerified: true },
	session: { id: `session-${id}`, userId: id },
});

describe.skipIf(!existsSync(fixturePath))(
	"platform release notifications in PostgreSQL",
	() => {
		const databaseName = `allauth_notices_${randomUUID().replaceAll("-", "")}`;
		let administrator: Pool;
		let database: Pool;
		let env: AuthEnvironment;
		const emails: string[] = [];
		const platformAnnouncements = platformReleases.map(
			(release) => release.announce,
		);
		beforeAll(async () => {
			// These SDK queue scenarios are independent of the current platform catalog;
			// the mixed SDK/platform announcement is exercised explicitly below.
			for (const release of platformReleases)
				Object.assign(release, { announce: false });
			const fixture = JSON.parse(readFileSync(fixturePath, "utf8")) as {
				container: string;
				DATABASE_URL: string;
			};
			const url = new URL(fixture.DATABASE_URL);
			if (
				fixture.container !== "allauth-production-test-20261007" ||
				url.hostname !== "127.0.0.1" ||
				url.port !== "55445"
			)
				throw new Error(
					"Only the isolated local AllAuth fixture is permitted.",
				);
			administrator = new Pool({
				connectionString: fixture.DATABASE_URL,
				max: 1,
			});
			await administrator.query(`CREATE DATABASE "${databaseName}"`);
			url.pathname = `/${databaseName}`;
			env = {
				DATABASE_URL: url.toString(),
				BETTER_AUTH_URL: "http://localhost:3000",
			};
			database = new Pool({ connectionString: url.toString(), max: 5 });
			for (const name of readdirSync(
				new URL("../../migrations", import.meta.url),
			)
				.filter((name) => name.endsWith(".sql"))
				.sort())
				await database.query(
					readFileSync(
						new URL(`../../migrations/${name}`, import.meta.url),
						"utf8",
					),
				);
			for (const id of [
				"owner",
				"admin",
				"member",
				"outsider",
				"unverified",
				"banned",
			]) {
				await database.query(
					'INSERT INTO public."user" (id,name,email,"emailVerified",banned,"createdAt","updatedAt") VALUES($1,$1,$2,$3,$4,$5,NOW())',
					[
						id,
						`${id}@fixture.example`,
						id !== "unverified",
						id === "banned",
						existingAccountAt,
					],
				);
				await database.query(
					'INSERT INTO public.session(id,token,"userId","expiresAt","createdAt","updatedAt") VALUES($1,$1,$2,NOW()+INTERVAL \'1 day\',NOW(),NOW())',
					[`session-${id}`, id],
				);
			}
			await database.query(
				"INSERT INTO public.\"allauthWorkspace\"(id,name,slug,\"createdBy\") VALUES('workspace','Workspace','workspace','owner')",
			);
			for (const [id, role] of [
				["owner", "owner"],
				["admin", "admin"],
				["member", "member"],
				["unverified", "admin"],
				["banned", "admin"],
			])
				await database.query(
					'INSERT INTO public."allauthWorkspaceMember"(id,"workspaceId","userId",role) VALUES($1,\'workspace\',$1,$2)',
					[id, role],
				);
			await database.query(
				"INSERT INTO public.\"allauthProject\"(id,name,slug,\"schemaName\",\"primaryOrigin\",origins,\"brokerClientId\",\"brokerSecret\",\"createdBy\",\"proxyVersion\",\"applicationId\",environment,\"workspaceId\") VALUES('project','Project','project-production','allauth_project_11111111111111111111111111111111','https://app.fixture.example','[]','fixture','encrypted','owner','fixture','project','production','workspace')",
			);
		}, 30000);
		afterAll(async () => {
			platformReleases.forEach((release, index) =>
				Object.assign(release, { announce: platformAnnouncements[index] }),
			);
			if (database) await database.end();
			if (administrator) {
				await administrator.query(`DROP DATABASE IF EXISTS "${databaseName}"`);
				await administrator.end();
			}
		});
		it("persists account-scoped reads and preferences without affecting another account", async () => {
			expect(
				(await listNotifications(principal("owner"), env, {}, database))
					.unreadCount,
			).toBe(1);
			await markNotificationsRead(
				principal("owner"),
				{ action: "mark-read", ids: [releaseId] },
				env,
				database,
			);
			expect(
				(await listNotifications(principal("owner"), env, {}, database))
					.unreadCount,
			).toBe(0);
			expect(
				(await listNotifications(principal("admin"), env, {}, database))
					.unreadCount,
			).toBe(1);
			await setNotificationPreferences(
				principal("admin"),
				false,
				env,
				database,
			);
			expect(
				(await listNotifications(principal("admin"), env, {}, database))
					.preferences.releaseEmails,
			).toBe(false);
			expect(
				(await listNotifications(principal("owner"), env, {}, database))
					.preferences.releaseEmails,
			).toBe(true);
			await expect(
				markNotificationsRead(
					principal("owner"),
					{ action: "mark-read", ids: ["forged-notification"] },
					env,
					database,
				),
			).rejects.toMatchObject({ statusCode: 400 });
			await markNotificationsRead(
				principal("outsider"),
				{ action: "mark-all-read" },
				env,
				database,
			);
			expect(
				(await listNotifications(principal("outsider"), env, {}, database))
					.unreadCount,
			).toBe(0);
			expect(
				(await listNotifications(principal("admin"), env, {}, database))
					.unreadCount,
			).toBe(1);
			await expect(
				listNotifications(principal("owner"), env, { limit: 101 }, database),
			).rejects.toThrow();
			await expect(
				listNotifications(principal("owner"), env, { offset: -1 }, database),
			).rejects.toThrow();
		});
		it("shows unknown versions honestly and scopes reported SDK versions to managed projects", async () => {
			const before = await listNotifications(
				principal("owner"),
				env,
				{},
				database,
			);
			expect(before.sdk.observed).toMatchObject([
				{
					projectId: "project",
					version: null,
					lastSeenAt: null,
					updateAvailable: null,
				},
			]);
			await recordSdkVersionObservation(
				{ id: "project" },
				"1.2.2",
				env,
				database,
			);
			expect(
				(await listNotifications(principal("owner"), env, {}, database)).sdk
					.observed,
			).toMatchObject([
				{ projectId: "project", version: "1.2.2", updateAvailable: true },
			]);
			expect(
				(await listNotifications(principal("outsider"), env, {}, database)).sdk
					.observed,
			).toEqual([]);
			expect(
				(await listNotifications(principal("member"), env, {}, database)).sdk
					.observed,
			).toEqual([]);
			await recordSdkVersionObservation(
				{ id: "project" },
				"forged header",
				env,
				database,
			);
			expect(
				(await listNotifications(principal("owner"), env, {}, database)).sdk
					.observed[0].version,
			).toBe("1.2.2");
		});
		it("rejects revoked or unverified platform principals", async () => {
			await expect(
				listNotifications(principal("unverified"), env, {}, database),
			).rejects.toMatchObject({ statusCode: 403 });
			await expect(
				listNotifications(principal("banned"), env, {}, database),
			).rejects.toMatchObject({ statusCode: 403 });
			await expect(
				listNotifications(
					{
						...principal("owner"),
						session: { id: "session-outsider", userId: "owner" },
					},
					env,
					{},
					database,
				),
			).rejects.toMatchObject({ statusCode: 403 });
		});
		it("durably queues one release email per eligible account and respects preferences on every retry", async () => {
			const send = async ({ to }: { to: string }) => {
				emails.push(to);
			};
			const options = { database, send, maxDeliveries: 10 };
			await Promise.all([
				deliverReleaseNotifications(env, options),
				deliverReleaseNotifications(env, options),
			]);
			await deliverReleaseNotifications(env, options);
			expect(emails).toEqual(["owner@fixture.example"]);
			const rows = (
				await database.query(
					'SELECT "userId","releaseId",status FROM public."allauthNotificationEmail" ORDER BY "userId"',
				)
			).rows;
			expect(rows).toEqual([
				{ userId: "owner", releaseId, status: "accepted" },
			]);
		});
		it("keeps historical release notices in a new account's inbox without emailing old releases", async () => {
			const createdAt = new Date(Date.parse(sdkReleases[0].publishedAt) + 1000);
			await database.query(
				'INSERT INTO public."user" (id,name,email,"emailVerified","createdAt","updatedAt") VALUES(\'new-owner\',\'New Owner\',\'new-owner@fixture.example\',true,$1,NOW())',
				[createdAt],
			);
			await database.query(
				"INSERT INTO public.session(id,token,\"userId\",\"expiresAt\",\"createdAt\",\"updatedAt\") VALUES('session-new-owner','session-new-owner','new-owner',NOW()+INTERVAL '1 day',NOW(),NOW())",
			);
			await database.query(
				"INSERT INTO public.\"allauthWorkspaceMember\"(id,\"workspaceId\",\"userId\",role) VALUES('new-owner','workspace','new-owner','admin')",
			);
			let sends = 0;
			const send = async () => {
				sends++;
			};
			await deliverReleaseNotifications(env, { database, send });
			expect(sends).toBe(0);
			expect(
				(
					await database.query(
						'SELECT id FROM public."allauthNotificationEmail" WHERE "userId"=\'new-owner\'',
					)
				).rows,
			).toEqual([]);
			expect(
				(await listNotifications(principal("new-owner"), env, {}, database))
					.notifications[0].id,
			).toBe(releaseId);
			// A pre-existing queued row must pass the same publication cutoff at send time.
			await database.query(
				'INSERT INTO public."allauthNotificationEmail"(id,"userId","releaseId") VALUES(\'historical-job\',\'new-owner\',$1)',
				[releaseId],
			);
			expect(
				await deliverReleaseNotifications(env, { database, send }),
			).toMatchObject({ claimed: 1, cancelled: 1 });
			expect(sends).toBe(0);
		});
		it("backs off provider failures and cancels a queued retry after an account opts out", async () => {
			await database.query(
				'INSERT INTO public."user" (id,name,email,"emailVerified","createdAt","updatedAt") VALUES(\'retry-owner\',\'Retry Owner\',\'retry-owner@fixture.example\',true,$1,NOW())',
				[existingAccountAt],
			);
			await database.query(
				"INSERT INTO public.session(id,token,\"userId\",\"expiresAt\",\"createdAt\",\"updatedAt\") VALUES('session-retry-owner','session-retry-owner','retry-owner',NOW()+INTERVAL '1 day',NOW(),NOW())",
			);
			await database.query(
				"INSERT INTO public.\"allauthWorkspaceMember\"(id,\"workspaceId\",\"userId\",role) VALUES('retry-owner','workspace','retry-owner','admin')",
			);
			const now = new Date();
			let sends = 0;
			const send = async () => {
				sends++;
				throw new Error("fixture delivery unavailable");
			};
			expect(
				await deliverReleaseNotifications(env, { database, now, send }),
			).toMatchObject({ claimed: 1, retried: 1, accepted: 0 });
			const queued = (
				await database.query(
					'SELECT status,attempts,"nextAttemptAt" FROM public."allauthNotificationEmail" WHERE "userId"=\'retry-owner\'',
				)
			).rows[0];
			expect(queued.status).toBe("pending");
			expect(queued.attempts).toBe(1);
			expect(queued.nextAttemptAt.getTime()).toBe(now.getTime() + 60_000);
			expect(
				await deliverReleaseNotifications(env, { database, now, send }),
			).toMatchObject({ claimed: 0 });
			await setNotificationPreferences(
				principal("retry-owner"),
				false,
				env,
				database,
			);
			expect(
				await deliverReleaseNotifications(env, {
					database,
					now: new Date(now.getTime() + 60_001),
					send,
				}),
			).toMatchObject({ claimed: 1, cancelled: 1 });
			expect(sends).toBe(1);
		});
		it("backfills public archive history without unread spam or retrospective email even when dates become known", async () => {
			await database.query(
				'INSERT INTO public."user" (id,name,email,"emailVerified","createdAt","updatedAt") VALUES(\'history-owner\',\'History Owner\',\'history-owner@fixture.example\',true,$1,NOW())',
				[existingAccountAt],
			);
			await database.query(
				"INSERT INTO public.session(id,token,\"userId\",\"expiresAt\",\"createdAt\",\"updatedAt\") VALUES('session-history-owner','session-history-owner','history-owner',NOW()+INTERVAL '1 day',NOW(),NOW())",
			);
			await database.query(
				"INSERT INTO public.\"allauthWorkspaceMember\"(id,\"workspaceId\",\"userId\",role) VALUES('history-owner','workspace','history-owner','admin')",
			);
			const historical = sdkReleases.filter((release) => !release.announce);
			const original = historical.map((release) => ({
				publishedAt: release.publishedAt,
				dateConfidence: release.dateConfidence,
			}));
			const recipients: string[] = [];
			try {
				// An accurately recovered old date must never turn a backfill into an announcement.
				for (const release of historical) {
					release.publishedAt = new Date(
						Date.parse(sdkReleases[0].publishedAt) - 3600_000,
					).toISOString();
					release.dateConfidence = "known";
				}
				const inbox = await listNotifications(
					principal("history-owner"),
					env,
					{},
					database,
				);
				expect(inbox.notifications.map((notice) => notice.id)).toEqual([
					releaseId,
				]);
				expect(inbox.unreadCount).toBe(1);
				await deliverReleaseNotifications(env, {
					database,
					maxDeliveries: 10,
					send: async ({ to }) => {
						recipients.push(to);
					},
				});
				expect(recipients).toEqual(["history-owner@fixture.example"]);
				expect(
					(
						await database.query(
							'SELECT "releaseId" FROM public."allauthNotificationEmail" WHERE "userId"=\'history-owner\'',
						)
					).rows,
				).toEqual([{ releaseId }]);
			} finally {
				historical.forEach((release, index) =>
					Object.assign(release, original[index]),
				);
			}
		});
		it("announces a new platform release through the same private inbox and eligible email outbox", async () => {
			const original = { ...platformReleases[0] };
			const announcement = {
				...original,
				id: "platform-fixture-update",
				slug: "platform-fixture-update",
				announce: true,
				title: "AllAuth platform fixture update",
				publishedAt: new Date().toISOString(),
				changelogUrl: "https://allauth.co/releases/platform-fixture-update",
			};
			const emails: { to: string; subject: string }[] = [];
			try {
				Object.assign(platformReleases[0], announcement);
				const inbox = await listNotifications(
					principal("history-owner"),
					env,
					{},
					database,
				);
				expect(inbox.notifications.map((notice) => notice.id)).toEqual([
					announcement.id,
					releaseId,
				]);
				expect(inbox.unreadCount).toBe(2);
				expect(inbox.sdk.latestVersion).toBe(sdkReleases[0].version);
				expect(inbox.notifications[0]).toMatchObject({
					kind: "platform-release",
					release: {
						compatibility: "platform-update",
						changelogUrl: announcement.changelogUrl,
					},
				});
				expect(inbox.notifications[1]).toMatchObject({
					kind: "sdk-release",
					release: {
						version: sdkReleases[0].version,
						compatibility: "backward-compatible",
						downloadUrl: sdkReleases[0].downloadUrl,
						sha256: sdkReleases[0].sha256,
					},
				});
				await markNotificationsRead(
					principal("history-owner"),
					{ action: "mark-read", ids: [announcement.id] },
					env,
					database,
				);
				expect(
					(
						await listNotifications(
							principal("history-owner"),
							env,
							{},
							database,
						)
					).unreadCount,
				).toBe(1);
				await deliverReleaseNotifications(env, {
					database,
					maxDeliveries: 10,
					send: async ({ to, subject }) => {
						emails.push({ to, subject });
					},
				});
				expect(emails.map((email) => email.to).sort()).toEqual([
					"history-owner@fixture.example",
					"new-owner@fixture.example",
					"owner@fixture.example",
				]);
				expect(
					emails.every((email) => email.subject === announcement.title),
				).toBe(true);
				await deliverReleaseNotifications(env, {
					database,
					maxDeliveries: 10,
					send: async ({ to, subject }) => {
						emails.push({ to, subject });
					},
				});
				expect(emails).toHaveLength(3);
			} finally {
				Object.assign(platformReleases[0], original);
			}
			expect(
				(
					await listNotifications(principal("history-owner"), env, {}, database)
				).notifications.map((notice) => notice.id),
			).toEqual([releaseId]);
		});
		it("applies the additive platform migration idempotently", async () => {
			const before = Number(
				(
					await database.query(
						'SELECT COUNT(*)::text AS total FROM public."allauthNotificationRead"',
					)
				).rows[0].total,
			);
			await database.query(
				readFileSync(
					new URL(
						"../../migrations/014-platform-notifications.sql",
						import.meta.url,
					),
					"utf8",
				),
			);
			expect(
				Number(
					(
						await database.query(
							'SELECT COUNT(*)::text AS total FROM public."allauthNotificationRead"',
						)
					).rows[0].total,
				),
			).toBe(before);
		});
	},
);

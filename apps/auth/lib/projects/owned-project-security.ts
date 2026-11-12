import { randomBytes, randomUUID } from "node:crypto";
import type { PoolClient } from "pg";
import {
	canonicalDomain,
	canonicalIP,
	defaultSecurityPolicy,
	securityPolicySchema,
	securitySubject,
	type SecurityPolicy,
} from "../control/security-policy";

type SecurityDatabase = Pick<PoolClient, "query">;

export const projectSecurityBlockedCode = "ALLAUTH_SECURITY_BLOCKED";

interface RequestIdentity {
	email?: string;
	username?: string;
}

interface SecurityOptions {
	secret: string;
	trustedIP(request: Request): string | null;
	requireTrustedIP?: boolean;
}

export function createOwnedProjectSecurity(options: SecurityOptions) {
	const trustedIP = (request: Request) =>
		canonicalIP(options.trustedIP(request));

	async function readPolicy(client: SecurityDatabase) {
		const { rows } = await client.query<{ policy: unknown }>(
			`SELECT policy FROM "allauthSecurityPolicy" WHERE id = 'default'`,
		);
		return rows[0]
			? securityPolicySchema.parse(rows[0].policy)
			: defaultSecurityPolicy;
	}

	async function record(
		client: SecurityDatabase,
		request: Request,
		type: string,
		outcome: "success" | "failure" | "blocked",
		metadata: Record<string, unknown>,
		userId?: string,
	) {
		await client.query(
			`INSERT INTO "allauthEvent" (id, type, outcome, "userId", "ipAddress", "userAgent", "createdAt", metadata)
			 VALUES ($1, $2, $3, $4, $5, $6, statement_timestamp(), $7)`,
			[
				randomUUID(),
				type,
				outcome,
				userId ?? null,
				trustedIP(request),
				request.headers.get("user-agent")?.slice(0, 512) ?? null,
				metadata,
			],
		);
	}

	async function blocked(
		client: SecurityDatabase,
		request: Request,
		policy: SecurityPolicy,
		signal: string,
		rule?: { id: string; type: string },
	) {
		const monitor = policy.mode === "monitor";
		await record(
			client,
			request,
			"security.blocked",
			monitor ? "success" : "blocked",
			{
				signal,
				monitor,
				...(rule ? { ruleId: rule.id, ruleType: rule.type } : {}),
			},
		);
		return !monitor;
	}

	async function checkRules(
		client: SecurityDatabase,
		request: Request,
		policy: SecurityPolicy,
		email?: string,
		ip?: string | null,
	) {
		const domain = email?.includes("@")
			? canonicalDomain(email.slice(email.lastIndexOf("@") + 1))
			: null;
		const { rows } = await client.query<{ id: string; type: string }>(
			`SELECT id, type FROM "allauthSecurityRule"
			 WHERE ("expiresAt" IS NULL OR "expiresAt" > statement_timestamp())
			   AND ((type = 'ip' AND value = $1) OR (type = 'email-domain' AND value = $2))
			 LIMIT 1`,
			[ip ?? null, domain],
		);
		if (rows[0])
			return blocked(client, request, policy, "explicit-rule", rows[0]);
		return domain && policy.blockedEmailDomains.includes(domain)
			? blocked(client, request, policy, "email-domain-policy")
			: false;
	}

	async function increment(
		client: SecurityDatabase,
		scope: string,
		subject: string,
		windowSeconds: number,
		limit: number,
		blockSeconds: number,
	) {
		const key = await securitySubject(options.secret, scope, subject);
		const current = new Date();
		const cutoff = new Date(current.getTime() - windowSeconds * 1000);
		const until = new Date(current.getTime() + blockSeconds * 1000);
		const { rows } = await client.query<{ count: number }>(
			`INSERT INTO "allauthSecurityCounter" AS c (key, scope, count, "windowStartedAt", "blockedUntil", "updatedAt")
			 VALUES ($1, $2, 1, $3, CASE WHEN $5::integer <= 1 THEN $6::timestamptz END, $3)
			 ON CONFLICT (key) DO UPDATE SET
			   count = CASE WHEN c."windowStartedAt" <= $4 THEN 1 ELSE LEAST(c.count::bigint + 1, 2147483647) END,
			   "windowStartedAt" = CASE WHEN c."windowStartedAt" <= $4 THEN $3 ELSE c."windowStartedAt" END,
			   "blockedUntil" = CASE
			     WHEN c."windowStartedAt" <= $4 THEN CASE WHEN $5::integer <= 1 THEN $6::timestamptz END
			     WHEN c.count::bigint + 1 >= $5 THEN $6::timestamptz
			     ELSE c."blockedUntil"
			   END,
			   "updatedAt" = $3
			 RETURNING count`,
			[key, scope, current, cutoff, limit, until],
		);
		return rows[0].count;
	}

	function failureSubjects(ip: string, identity?: RequestIdentity) {
		const identifier = identity?.email
			? `email:${identity.email}`
			: identity?.username
				? `username:${identity.username}`
				: null;
		return identifier
			? ([
					["fail-ip", ip],
					["fail-ip-identity", `${ip}\0${identifier}`],
				] as const)
			: ([["fail-ip", ip]] as const);
	}

	async function pruneExpiredState(client: SecurityDatabase) {
		await client.query(
			`DELETE FROM "allauthSecurityCounter" WHERE key IN (
				SELECT key FROM "allauthSecurityCounter"
				WHERE "updatedAt" < statement_timestamp() - interval '2 days'
					AND ("blockedUntil" IS NULL OR "blockedUntil" < statement_timestamp())
				LIMIT 500
			 )`,
		);
		await client.query(
			`DELETE FROM "allauthKnownDevice" WHERE id IN (
				SELECT id FROM "allauthKnownDevice"
				WHERE "lastSeenAt" < statement_timestamp() - interval '180 days'
				LIMIT 100
			 )`,
		);
	}

	async function admit(
		client: SecurityDatabase,
		request: Request,
		input?: RequestIdentity & { message?: boolean; signup?: boolean },
	) {
		const policy = await readPolicy(client);
		const ip = trustedIP(request);
		if (!ip && options.requireTrustedIP) {
			return blocked(client, request, policy, "missing-trusted-ip");
		}
		await pruneExpiredState(client);
		if (await checkRules(client, request, policy, input?.email, ip))
			return true;
		if (!ip) return false;
		const subjects = failureSubjects(ip, input);
		const keys = await Promise.all(
			subjects.map(([scope, subject]) =>
				securitySubject(options.secret, scope, subject),
			),
		);
		const { rowCount } = await client.query(
			`SELECT 1 FROM "allauthSecurityCounter"
			 WHERE key = ANY($1::text[]) AND "blockedUntil" > statement_timestamp() LIMIT 1`,
			[keys],
		);
		if (
			rowCount &&
			(await blocked(client, request, policy, "credential-failure-limit"))
		)
			return true;
		if (input?.message) {
			const limit = policy.maxSignUpsPerIp * 5;
			if (
				(await increment(
					client,
					"request-ip",
					ip,
					policy.signUpWindowSeconds,
					limit,
					policy.blockSeconds,
				)) > limit
			) {
				if (
					await blocked(
						client,
						request,
						policy,
						"authentication-message-velocity",
					)
				)
					return true;
			}
		}
		if (input?.signup) {
			const limit = policy.maxSignUpsPerIp;
			if (
				(await increment(
					client,
					"signup-ip",
					ip,
					policy.signUpWindowSeconds,
					limit,
					policy.blockSeconds,
				)) > limit
			) {
				return blocked(client, request, policy, "signup-velocity");
			}
		}
		return false;
	}

	async function failed(
		client: SecurityDatabase,
		request: Request,
		path: string,
		identity?: RequestIdentity,
	) {
		const policy = await readPolicy(client);
		const ip = trustedIP(request);
		if (ip) {
			for (const [scope, subject] of failureSubjects(ip, identity)) {
				await increment(
					client,
					scope,
					subject,
					policy.failureWindowSeconds,
					policy.maxFailuresPerIp,
					policy.blockSeconds,
				);
			}
		}
		await record(client, request, "security.sign-in-failed", "failure", {
			method: path.split("/").pop(),
			path,
		});
	}

	async function registerDevice(
		client: SecurityDatabase,
		request: Request,
		userId: string,
		cookie: string | null,
	) {
		const token =
			cookie && /^[a-f\d]{64}$/.test(cookie)
				? cookie
				: randomBytes(32).toString("hex");
		const hash = await securitySubject(options.secret, "device", token);
		await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", [
			`allauth-device:${userId}`,
		]);
		const updated = await client.query(
			`UPDATE "allauthKnownDevice" SET "lastSeenAt" = statement_timestamp()
			 WHERE "userId" = $1 AND "deviceHash" = $2`,
			[userId, hash],
		);
		if (updated.rowCount) return { token, notify: false };
		const previous = await client.query(
			`SELECT 1 FROM "allauthKnownDevice" WHERE "userId" = $1 LIMIT 1`,
			[userId],
		);
		await client.query(
			`INSERT INTO "allauthKnownDevice" (id, "userId", "deviceHash", "createdAt", "lastSeenAt")
			 VALUES ($1, $2, $3, statement_timestamp(), statement_timestamp())`,
			[randomUUID(), userId, hash],
		);
		await client.query(
			`DELETE FROM "allauthKnownDevice" WHERE id IN (
				SELECT id FROM "allauthKnownDevice" WHERE "userId" = $1 ORDER BY "lastSeenAt" DESC OFFSET 20
			 )`,
			[userId],
		);
		if (!previous.rowCount) return { token, notify: false };
		await record(
			client,
			request,
			"security.new-device",
			"success",
			{ newDevice: true },
			userId,
		);
		return { token, notify: (await readPolicy(client)).newDeviceNotifications };
	}

	return {
		admit,
		failed,
		registerDevice,
		trustedIP,
		async denySession(
			client: SecurityDatabase,
			request: Request,
			email: string,
		) {
			return checkRules(client, request, await readPolicy(client), email);
		},
		async notificationFailed(
			client: SecurityDatabase,
			request: Request,
			userId: string,
		) {
			await record(
				client,
				request,
				"security.new-device-notification-failed",
				"failure",
				{},
				userId,
			);
		},
	};
}

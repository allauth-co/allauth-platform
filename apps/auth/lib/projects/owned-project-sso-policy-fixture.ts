import { randomUUID } from "node:crypto";
import type { Pool } from "pg";
import { expect } from "vitest";
import {
	defaultSecurityPolicy,
	securitySubject,
} from "../control/security-policy";

type SsoFixtureIdentity = {
	ip: string;
	providerId: string;
	subject: string;
	email: string;
	errorURL?: string;
};

/** Exercise the native and owned callbacks against the same realm and durable buckets. */
export async function checkSsoPolicyFixture(options: {
	database: Pool;
	schema: string;
	secret: string;
	origin: string;
	destination: string;
	defaultErrorURL: string;
	managedProvider: string;
	managedSubject: string;
	signupProvider: string;
	signIn(
		writer: "native" | "owned",
		input: SsoFixtureIdentity,
	): Promise<Response>;
}) {
	const { database, schema, secret, signIn, destination } = options;
	const scope = `"${schema}"`;
	const profileDomain = "restricted.corp.example";
	const errorURL = `${options.origin}/auth-error?from=security-policy`;
	const rule = randomUUID();
	const storedRule = randomUUID();
	const checkCounter = async (ip: string, kind: string) =>
		(
			await database.query<{ count: number }>(
				`SELECT count FROM ${scope}."allauthSecurityCounter" WHERE key=$1`,
				[await securitySubject(secret, kind, ip)],
			)
		).rows[0]?.count ?? 0;
	const accounts = ({ providerId, subject }: SsoFixtureIdentity) =>
		database.query<{ userId: string }>(
			`SELECT id,"userId","accessToken","refreshToken","idToken","updatedAt"
			 FROM ${scope}."account" WHERE "providerId"=$1 AND "accountId"=$2 ORDER BY id`,
			[providerId, subject],
		);
	const noAccount = async (identity: SsoFixtureIdentity) => {
		expect((await accounts(identity)).rows).toEqual([]);
		expect(
			(
				await database.query(`SELECT id FROM ${scope}."user" WHERE email=$1`, [
					identity.email,
				])
			).rows,
		).toEqual([]);
	};
	const assertDenial = (
		response: Response,
		base: string,
		code: string,
		description: string,
	) => {
		expect(response.status).toBe(302);
		expect(
			response.headers
				.getSetCookie()
				.some((value) => value.includes(".session_token=")),
		).toBe(false);
		const target = new URL(base);
		target.searchParams.set("error", code);
		target.searchParams.set("error_description", description);
		expect(response.headers.get("location")).toBe(target.href);
	};
	const addRule = (id: string, domain: string) =>
		database.query(
			`INSERT INTO ${scope}."allauthSecurityRule" (id,type,value,reason)
			 VALUES ($1,'email-domain',$2,'Synthetic SSO rule')`,
			[id, domain],
		);
	const ruleEvents = (ip: string) =>
		database.query(
			`SELECT id FROM ${scope}."allauthEvent"
			 WHERE type='security.blocked' AND "ipAddress"=$1`,
			[ip],
		);
	try {
		await database.query(
			`INSERT INTO ${scope}."allauthSecurityPolicy" (id,policy) VALUES ('default',$1)`,
			[{ ...defaultSecurityPolicy, maxSignUpsPerIp: 1 }],
		);
		await addRule(rule, profileDomain);
		const managed = {
			ip: "192.0.2.174",
			providerId: options.managedProvider,
			subject: options.managedSubject,
			email: "allowed@unmanaged.fixture.example",
		};
		const seeded = await signIn("native", managed);
		expect(seeded.headers.get("location")).toBe(destination);
		const before = (await accounts(managed)).rows;
		expect(before).toHaveLength(1);
		const managedSessions = () =>
			database.query(
				`SELECT id FROM ${scope}."session" WHERE "userId"=$1 ORDER BY id`,
				[before[0]!.userId],
			);
		const sessionsBefore = (await managedSessions()).rows;
		for (const [index, writer] of (["native", "owned"] as const).entries()) {
			const other = writer === "native" ? "owned" : "native";
			const ip = `192.0.2.${175 + index}`;
			const rejectProfile = (response: Response, target = errorURL) =>
				assertDenial(
					response,
					target,
					"validation_failed",
					"User validation failed",
				);
			rejectProfile(
				await signIn(writer, {
					...managed,
					ip,
					email: `profile@${profileDomain}`,
					errorURL,
				}),
			);
			expect((await accounts(managed)).rows).toEqual(before);
			const signup = { ip, providerId: options.signupProvider, errorURL };
			const blocked = {
				...signup,
				email: `signup-${index}@${profileDomain}`,
				subject: randomUUID(),
			};
			rejectProfile(await signIn(writer, blocked));
			await noAccount(blocked);
			expect(await checkCounter(ip, "signup-ip")).toBe(0);

			const valid = {
				...signup,
				email: `signup-${index}@corp.example`,
				subject: randomUUID(),
			};
			expect((await signIn(writer, valid)).headers.get("location")).toBe(
				destination,
			);
			expect(await checkCounter(ip, "signup-ip")).toBe(1);
			expect((await signIn(other, valid)).headers.get("location")).toBe(
				destination,
			);
			expect(await checkCounter(ip, "signup-ip")).toBe(1);

			const exceeded = {
				...signup,
				errorURL: undefined,
				email: `velocity-${index}@corp.example`,
				subject: randomUUID(),
			};
			rejectProfile(await signIn(other, exceeded), options.defaultErrorURL);
			await noAccount(exceeded);
			expect(await checkCounter(ip, "signup-ip")).toBe(2);
			expect(await checkCounter(ip, "fail-ip")).toBe(3);
			expect((await ruleEvents(ip)).rows).toEqual([]);
		}
		await addRule(storedRule, "corp.example");
		for (const writer of ["native", "owned"] as const) {
			assertDenial(
				await signIn(writer, { ...managed, errorURL }),
				errorURL,
				"ALLAUTH_SECURITY_BLOCKED",
				"This authentication request is temporarily unavailable. Try again later.",
			);
			expect((await accounts(managed)).rows).toEqual(before);
			expect(await checkCounter(managed.ip, "signup-ip")).toBe(0);
			expect((await ruleEvents(managed.ip)).rows).toEqual([]);
			expect((await managedSessions()).rows).toEqual(sessionsBefore);
		}
	} finally {
		await database.query(
			`DELETE FROM ${scope}."allauthSecurityRule" WHERE id=ANY($1::text[])`,
			[[rule, storedRule]],
		);
		await database.query(
			`DELETE FROM ${scope}."allauthSecurityPolicy" WHERE id='default'`,
		);
	}
}

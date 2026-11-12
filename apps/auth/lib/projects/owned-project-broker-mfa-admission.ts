import { randomUUID } from "node:crypto";
import type { PoolClient } from "pg";
import { canonicalIP } from "../control/security-policy";

export const projectBrokerMfaPath = "/broker-two-factor/verify";
const maximum = 100;
const windowMs = 60_000;

function admissionAddress(value: string | null) {
	const ip = canonicalIP(value);
	if (!ip) return "no-trusted-ip";
	if (!ip.includes(":")) return ip;
	// Native rate limiting stores expanded IPv6 addresses masked to their /64.
	const [head = "", tail] = ip.split("::");
	const left = head ? head.split(":") : [];
	const right = tail ? tail.split(":") : [];
	const groups =
		tail === undefined
			? left
			: [
					...left,
					...Array<string>(8 - left.length - right.length).fill("0"),
					...right,
				];
	return [...groups.slice(0, 4), "0", "0", "0", "0"]
		.map((group) => group.padStart(4, "0"))
		.join(":");
}

/** Consume the same persisted rate-limit window as the legacy broker MFA route. */
export async function admitOwnedProjectBrokerMfa(
	client: PoolClient,
	ip: string | null,
): Promise<Response | null> {
	const key = `${admissionAddress(ip)}|${projectBrokerMfaPath}`;
	const admitted = await client.query(
		`INSERT INTO "rateLimit" (id, "key", count, "lastRequest")
		 VALUES ($1, $2, 1, floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint)
		 ON CONFLICT ("key") DO UPDATE SET (count, "lastRequest") = (
			 SELECT CASE WHEN "rateLimit"."lastRequest" <= instant - $3 THEN 1 ELSE "rateLimit".count + 1 END, instant
			 FROM (SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint AS instant) clock
		 )
		 WHERE "rateLimit"."lastRequest" <= floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint - $3
			 OR "rateLimit".count < $4`,
		[randomUUID(), key, windowMs, maximum],
	);
	if (admitted.rowCount === 1) return null;
	// ON CONFLICT keeps the row locked. A second statement can see a bucket
	// another transaction created while this one waited for that lock.
	const {
		rows: [result],
	} = await client.query<{ retryAfter: number }>(
		`SELECT greatest(1, ceil(("lastRequest" + $2 - extract(epoch FROM clock_timestamp()) * 1000) / 1000))::int AS "retryAfter"
		 FROM "rateLimit" WHERE "key" = $1`,
		[key, windowMs],
	);
	if (!result) throw new Error("Broker MFA admission is unavailable.");
	return Response.json(
		{ message: "Too many requests. Please try again later." },
		{
			status: 429,
			statusText: "Too Many Requests",
			headers: { "X-Retry-After": String(result.retryAfter) },
		},
	);
}

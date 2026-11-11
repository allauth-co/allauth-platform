import { randomUUID } from "node:crypto";
import type { Pool } from "pg";

export interface SessionCheckAdmission {
	allowed: boolean;
	retryAfter: number;
}

export interface SessionCheckRule {
	/** Maximum steady admission over window seconds. */
	max: number;
	/** Sustained-rate interval in seconds. */
	window: number;
	/** Immediate work allowance after an idle period. */
	burst?: number;
}

/** Shared across service replicas; only verified session-check work uses this rule. */
export const proxySessionCheckRule = Object.freeze({
	max: 1200,
	window: 60,
	burst: 120,
});

/**
 * Atomic continuous-refill admission using the realm's existing rate-limit table and DB clock.
 * lastRequest stores theoretical arrival time, at most one burst into the future.
 * This timestamp remains compatible with native expired-row cleanup: a row old
 * enough to delete has already regained its full burst. Use a versioned key
 * namespace so older service replicas cannot interpret this row as a fixed window.
 */
export async function consumeProxySessionCheck(
	database: Pick<Pool, "query">,
	key: string,
	rule: SessionCheckRule = proxySessionCheckRule,
): Promise<SessionCheckAdmission> {
	const burst = rule.burst ?? rule.max;
	if (
		!Number.isSafeInteger(rule.max) ||
		rule.max < 1 ||
		!Number.isSafeInteger(rule.window) ||
		rule.window < 1 ||
		!Number.isSafeInteger(burst) ||
		burst < 1
	)
		throw new Error("Invalid session-check admission rule.");
	// Rounding up can only make admission more conservative. The conflict-update
	// clock is sampled after its row lock so a queued caller sees current refill.
	const interval = Math.ceil((rule.window * 1000) / rule.max);
	const tolerance = (burst - 1) * interval;
	if (!Number.isSafeInteger(interval) || !Number.isSafeInteger(tolerance))
		throw new Error("Invalid session-check admission rule.");
	const result = await database.query<{ allowed: boolean; retryAfter: number }>(
		`INSERT INTO "rateLimit" (id,"key","count","lastRequest")
		VALUES ($1,$2,1,floor(extract(epoch FROM clock_timestamp())*1000)::bigint+$3)
		ON CONFLICT ("key") DO UPDATE SET ("count","lastRequest") = (
			WITH clock AS MATERIALIZED (
				SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint AS now
			)
			SELECT CASE WHEN "rateLimit"."lastRequest"<=now+$4 THEN 1 ELSE 0 END,
				CASE WHEN "rateLimit"."lastRequest"<=now+$4
					THEN greatest("rateLimit"."lastRequest",now)+$3
					ELSE "rateLimit"."lastRequest" END
			FROM clock
		)
		RETURNING "count"=1 AS allowed,
			CASE WHEN "count"=1 THEN 0 ELSE greatest(1,ceil(("lastRequest"-$4-floor(extract(epoch FROM clock_timestamp())*1000))/1000.0))::integer END AS "retryAfter"`,
		[randomUUID(), key, interval, tolerance],
	);
	const admission = result.rows[0];
	if (!admission) throw new Error("Session-check admission is unavailable.");
	return admission;
}

import * as z from "zod";
import type { SecurityPolicy } from "./security-policy";
import {
	canonicalDomain,
	canonicalIP,
	defaultSecurityPolicy,
	securityPolicySchema,
} from "./security-policy";

export const securityUpdateInput = z
	.object({ policy: securityPolicySchema })
	.strict();
export const securityRuleAddInput = z
	.object({
		type: z.enum(["ip", "email-domain"]),
		value: z.string().min(1).max(253),
		reason: z.string().trim().min(1).max(200),
		expiresAt: z.iso.datetime({ offset: true }).optional(),
	})
	.strict();
export const securityRuleRemoveInput = z
	.object({ id: z.string().uuid() })
	.strict();

export const invalidSecurityRuleMessage =
	"Supply a valid IP or email domain and an optional expiry within one year.";

export interface SecurityRule {
	id: string;
	type: "ip" | "email-domain";
	value: string;
	reason: string;
	expiresAt?: string;
	createdAt: string;
}

type SecurityRuleRow = Omit<SecurityRule, "expiresAt" | "createdAt"> & {
	expiresAt: Date | null;
	createdAt: Date;
};

interface SecurityManagementDatabase {
	query<Row extends object>(
		text: string,
		values: unknown[],
	): Promise<{ rows: Row[] }>;
}

function publicRule(row: SecurityRuleRow): SecurityRule {
	return {
		id: row.id,
		type: row.type,
		value: row.value,
		reason: row.reason,
		...(row.expiresAt ? { expiresAt: row.expiresAt.toISOString() } : {}),
		createdAt: row.createdAt.toISOString(),
	};
}

/** The two project writers share the persisted policy, rule normalization, and dashboard projection. */
export function controlSecurityManagementRepository(
	database: SecurityManagementDatabase,
	now = () => new Date(),
) {
	async function getPolicy(): Promise<SecurityPolicy> {
		const { rows } = await database.query<{ policy: unknown }>(
			`SELECT policy FROM "allauthSecurityPolicy" WHERE id='default'`,
			[],
		);
		return rows[0]
			? securityPolicySchema.parse(rows[0].policy)
			: { ...defaultSecurityPolicy, blockedEmailDomains: [] };
	}

	async function updatePolicy(input: unknown) {
		const policy = securityPolicySchema.parse(input);
		policy.blockedEmailDomains = [...new Set(policy.blockedEmailDomains)];
		await database.query(
			`INSERT INTO "allauthSecurityPolicy" (id,policy,"updatedAt") VALUES ('default',$1::jsonb,$2)
			 ON CONFLICT (id) DO UPDATE SET policy=EXCLUDED.policy,"updatedAt"=EXCLUDED."updatedAt"`,
			[JSON.stringify(policy), now()],
		);
		return policy;
	}

	async function report(capabilities: {
		newDeviceNotifications: boolean;
		breachedPasswords: boolean;
	}) {
		const current = now();
		const [policy, rules, stats] = await Promise.all([
			getPolicy(),
			database.query<SecurityRuleRow>(
				`SELECT id,type,value,reason,"expiresAt","createdAt" FROM "allauthSecurityRule"
				 WHERE "expiresAt" IS NULL OR "expiresAt" > $1 ORDER BY "createdAt" DESC LIMIT 500`,
				[current],
			),
			database.query<{ blockedRequests: string; last24hFailures: string }>(
				`SELECT COUNT(*) FILTER (WHERE type='security.blocked' AND outcome='blocked') AS "blockedRequests",
				 COUNT(*) FILTER (WHERE type='security.sign-in-failed') AS "last24hFailures"
				 FROM "allauthEvent" WHERE "createdAt" >= $1`,
				[new Date(current.getTime() - 86_400_000)],
			),
		]);
		return {
			policy,
			rules: rules.rows.map(publicRule),
			stats: {
				blockedRequests: Number(stats.rows[0]?.blockedRequests || 0),
				last24hFailures: Number(stats.rows[0]?.last24hFailures || 0),
				activeRules: rules.rows.length,
			},
			capabilities: {
				credentialStuffing: true,
				velocity: true,
				blockRules: true,
				newDeviceNotifications: capabilities.newDeviceNotifications,
				botChallenge: false,
				impossibleTravel: false,
				breachedPasswords: capabilities.breachedPasswords,
			},
		};
	}

	async function addRule(input: z.infer<typeof securityRuleAddInput>) {
		const current = now();
		const value =
			input.type === "ip"
				? canonicalIP(input.value)
				: canonicalDomain(input.value);
		const expiresAt = input.expiresAt ? new Date(input.expiresAt) : null;
		if (
			!value ||
			(expiresAt &&
				(expiresAt <= current ||
					expiresAt.getTime() > current.getTime() + 365 * 86_400_000))
		)
			return null;
		const { rows } = await database.query<SecurityRuleRow>(
			`INSERT INTO "allauthSecurityRule" (id,type,value,reason,"expiresAt","createdAt")
			 VALUES ($1,$2,$3,$4,$5,$6)
			 ON CONFLICT (type,value) DO UPDATE SET reason=EXCLUDED.reason,"expiresAt"=EXCLUDED."expiresAt"
			 RETURNING id,type,value,reason,"expiresAt","createdAt"`,
			[
				crypto.randomUUID(),
				input.type,
				value,
				input.reason,
				expiresAt,
				current,
			],
		);
		if (!rows[0]) throw new Error("Security rule could not be saved.");
		return publicRule(rows[0]);
	}

	async function removeRule(id: string) {
		await database.query(`DELETE FROM "allauthSecurityRule" WHERE id=$1`, [id]);
	}

	return { getPolicy, updatePolicy, report, addRule, removeRule };
}

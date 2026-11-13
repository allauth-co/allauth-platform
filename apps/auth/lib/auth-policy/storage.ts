import { APIError } from "better-auth";
import { randomUUID } from "node:crypto";
import type { Pool } from "pg";
import type { AuthEnvironment } from "../configuration";
import { storedProjectWebhookSelectors } from "../projects/owned-project-webhook-admission";
import type { ProjectEngineWriter } from "../projects/project-engine-writer-lease";
import { projectRegistryPool } from "../projects/registry";
import { checkedProjectSchema } from "../projects/validation";
import { authPolicySchema, defaultStoredAuthPolicy } from "./policy";
import type { AuthPolicy, StoredAuthPolicy } from "./policy";

interface PolicyRow { version: number; policy: unknown; updatedAt: Date }
const publicPolicy = (row?: PolicyRow): StoredAuthPolicy => row ? { version: row.version, policy: authPolicySchema.parse(row.policy), updatedAt: new Date(row.updatedAt).toISOString() } : defaultStoredAuthPolicy();
/** All policies are in the platform registry, independent of the current adapter/search_path. */
export function authPolicyRepository(pool: Pick<Pool, "query">) {
	return {
		async read(scopeId: string): Promise<StoredAuthPolicy> {
			const result = await pool.query<PolicyRow>('SELECT version,policy,"updatedAt" FROM public."allauthAuthConfiguration" WHERE id=$1', [scopeId]);
			return publicPolicy(result.rows[0]);
		},
		async update(scopeId: string, expectedVersion: number, policy: AuthPolicy, actorId: string, auditSchema?: string, writer?: ProjectEngineWriter): Promise<StoredAuthPolicy> {
			const validated = authPolicySchema.parse(policy);
			if (writer === "allauth") {
				const configuration = await storedProjectWebhookSelectors(pool, auditSchema ?? "", validated);
				if (configuration?.unsupported !== false)
					throw new APIError("CONFLICT", { message: "Switch this project to the legacy writer before saving a policy that its configured webhooks cannot support." });
			}
			let statement = expectedVersion === 0
				? 'INSERT INTO public."allauthAuthConfiguration" (id,policy,version,"updatedBy") VALUES ($1,$2,1,$3) ON CONFLICT (id) DO NOTHING RETURNING version,policy,"updatedAt"'
				: 'UPDATE public."allauthAuthConfiguration" SET policy=$2,version=version+1,"updatedBy"=$3,"updatedAt"=NOW() WHERE id=$1 AND version=$4 RETURNING version,policy,"updatedAt"';
			const values: unknown[] = [scopeId, JSON.stringify(validated), actorId, ...(expectedVersion === 0 ? [] : [expectedVersion])];
			if (auditSchema) {
				const schema = auditSchema === "public" ? auditSchema : checkedProjectSchema(auditSchema);
				values.push(randomUUID());
				// One PostgreSQL statement makes policy/version and the immutable scoped
				// audit event atomic. A stale save neither updates nor records an event.
				statement = `WITH updated AS (${statement}), audited AS (INSERT INTO "${schema}"."allauthEvent" (id,type,outcome,"actorId","targetId","createdAt",metadata) SELECT $${values.length},'configuration.updated','success',$3,$1,NOW(),jsonb_build_object('action','authentication-policy','version',updated.version) FROM updated RETURNING id) SELECT updated.version,updated.policy,updated."updatedAt" FROM updated CROSS JOIN audited`;
			}
			const result = await pool.query<PolicyRow>(statement,values);
			if (!result.rows[0]) throw new APIError("CONFLICT", { message: "Settings changed. Reload them before saving again." });
			return publicPolicy(result.rows[0]);
		},
	};
}
export const readAuthPolicy = (scopeId: string, env: AuthEnvironment) => authPolicyRepository(projectRegistryPool(env)).read(scopeId);

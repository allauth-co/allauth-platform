import { createHmac, randomUUID } from "node:crypto";
import { APIError } from "better-auth";
import { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";
import type { Pool } from "pg";
import { setting } from "../configuration";
import type { AuthEnvironment } from "../configuration";
import { projectRegistryPool } from "../projects/registry";
import type { Project } from "../projects/registry";
import { checkedProjectSchema } from "../projects/validation";
import { defaultGoogleProvider, googleProviderPatch } from "./google";
import type { GoogleProviderCredentials, GoogleProviderPatch, StoredGoogleProvider } from "./google";

interface ProviderRow { version: number; enabled: boolean; clientId: string; encryptedClientSecret: string; updatedAt: Date }
function publicStored(row?: ProviderRow): StoredGoogleProvider {
	return row ? { version: row.version, enabled: row.enabled, clientId: row.clientId, encryptedClientSecret: row.encryptedClientSecret, updatedAt: new Date(row.updatedAt).toISOString() } : defaultGoogleProvider();
}
function providerKey(projectId: string, env: AuthEnvironment) {
	const secret = setting(env, "BETTER_AUTH_SECRET");
	if (secret.length < 32) throw new Error("Provider encryption requires the platform authentication secret.");
	return createHmac("sha256", secret).update(`allauth:project-google:${projectId}`).digest("hex");
}
/** Credentials are encrypted with a project-bound key and never enter a public settings response. */
export const encryptGoogleSecret = (value: string, projectId: string, env: AuthEnvironment) => symmetricEncrypt({ key: providerKey(projectId, env), data: value });
export const decryptGoogleSecret = (value: string, projectId: string, env: AuthEnvironment) => symmetricDecrypt({ key: providerKey(projectId, env), data: value });

export function googleProviderRepository(pool: Pick<Pool, "query">, env: AuthEnvironment) {
	const read = async (projectId: string): Promise<StoredGoogleProvider> => publicStored((await pool.query<ProviderRow>('SELECT version,enabled,"clientId","encryptedClientSecret","updatedAt" FROM public."allauthProjectGoogleProvider" WHERE "projectId"=$1', [projectId])).rows[0]);
	return {
		read,
		async update(project: Pick<Project, "id" | "schemaName">, input: GoogleProviderPatch, actorId: string): Promise<StoredGoogleProvider> {
			const value = googleProviderPatch.parse(input);
			const before = await read(project.id);
			if (before.version !== value.version) throw new APIError("CONFLICT", { message: "Settings changed. Reload them before saving again." });
			const clientId = value.google.clientId || before.clientId;
			const encrypted = value.google.clientSecret ? await encryptGoogleSecret(value.google.clientSecret, project.id, env) : before.encryptedClientSecret;
			if (value.google.enabled && (!clientId || !encrypted)) throw new APIError("BAD_REQUEST", { message: "Direct Google sign-in requires a Google web client ID and client secret." });
			const schema = checkedProjectSchema(project.schemaName);
			const statement = value.version === 0
				? 'INSERT INTO public."allauthProjectGoogleProvider" ("projectId",enabled,"clientId","encryptedClientSecret",version,"updatedBy") VALUES ($1,$2,$3,$4,1,$5) ON CONFLICT ("projectId") DO NOTHING RETURNING version,enabled,"clientId","encryptedClientSecret","updatedAt"'
				: 'UPDATE public."allauthProjectGoogleProvider" SET enabled=$2,"clientId"=$3,"encryptedClientSecret"=$4,version=version+1,"updatedBy"=$5,"updatedAt"=NOW() WHERE "projectId"=$1 AND version=$6 RETURNING version,enabled,"clientId","encryptedClientSecret","updatedAt"';
			const values: unknown[] = [project.id, value.google.enabled, clientId, encrypted, actorId, ...(value.version === 0 ? [] : [value.version])];
			values.push(randomUUID());
			const audited = `WITH updated AS (${statement}), audited AS (INSERT INTO "${schema}"."allauthEvent" (id,type,outcome,"actorId","targetId","createdAt",metadata) SELECT $${values.length},'configuration.updated','success',$5,$1,NOW(),jsonb_build_object('action','google-provider','version',updated.version) FROM updated RETURNING id) SELECT updated.* FROM updated CROSS JOIN audited`;
			const row = (await pool.query<ProviderRow>(audited, values)).rows[0];
			if (!row) throw new APIError("CONFLICT", { message: "Settings changed. Reload them before saving again." });
			return publicStored(row);
		},
	};
}
export const readGoogleProvider = (projectId: string, env: AuthEnvironment) => googleProviderRepository(projectRegistryPool(env), env).read(projectId);
/** Only the server runtime may unwrap a configured environment's provider credential. */
export async function googleProviderCredentials(stored: StoredGoogleProvider, projectId: string, env: AuthEnvironment): Promise<GoogleProviderCredentials | undefined> {
	if (!stored.enabled) return undefined;
	if (!stored.clientId || !stored.encryptedClientSecret) throw new Error("The direct Google provider is incomplete.");
	return { clientId: stored.clientId, clientSecret: await decryptGoogleSecret(stored.encryptedClientSecret, projectId, env) };
}

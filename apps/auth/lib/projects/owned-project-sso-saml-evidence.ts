import { createHash, createHmac } from "node:crypto";
import type { Pool } from "pg";
import * as z from "zod";
import type { AuthEnvironment } from "../configuration";
import { authOrigin, setting } from "../configuration";
import { readStoredSsoConfiguration } from "./owned-project-sso-projection";
import { configureProjectSamlTransport } from "./owned-project-sso-saml-eligibility";
import { verifyOwnedSaml } from "./owned-project-sso-saml-protocol";
import { createProjectCustomSamlTransport } from "./owned-project-sso-saml-transport";
import {
	sameSsoProvider,
	ssoProviderId,
	ssoReferenceSchema,
	ssoStateSchema,
} from "./owned-project-sso-store";
import {
	internalProjectEngineSelected,
	internalProjectPreparationRevision,
} from "./project-engine-internal-selection";
import { createProjectEngineWriterLease } from "./project-engine-writer-lease";
import type { Project } from "./registry";
import { checkedProjectSchema } from "./validation";

const sample = z.strictObject({
	receiver: z.url().max(2048),
	samlResponse: z
		.string()
		.min(1)
		.max(256 * 1024),
	relayState: z.string().regex(/^[A-Za-z0-9_-]{32,80}$/),
});
const pendingRequest = z.strictObject({
	id: z.string(),
	providerId: ssoProviderId,
	providerReference: ssoReferenceSchema,
	createdAt: z.number().int(),
	expiresAt: z.number().int(),
});

function unverified(): never {
	throw new Error("The encrypted SAML preflight sample could not be verified.");
}

/** Inspect one pending native response on the protected legacy writer. The receipt cannot select a writer. */
export async function verifyProjectEncryptedSamlEvidence(options: {
	database: Pool;
	project: Project;
	env: AuthEnvironment;
	providerId: string;
	input: unknown;
}) {
	const { database, project, env } = options;
	const providerInput = ssoProviderId.safeParse(options.providerId);
	const parsed = sample.safeParse(options.input);
	const secret = setting(env, "ALLAUTH_AUTH_SECRET");
	if (
		!providerInput.success ||
		!parsed.success ||
		!secret ||
		!internalProjectEngineSelected(env, project) ||
		database.options.connectionString !== setting(env, "DATABASE_URL")
	)
		unverified();
	const providerId = providerInput.data;
	const { receiver, samlResponse, relayState } = parsed.data;
	const schema = checkedProjectSchema(project.schemaName);
	const lease = createProjectEngineWriterLease({
		database,
		project,
		selectedProjectId: project.id,
	});
	return lease.run("legacy", async ({ revision }) => {
		if (revision !== internalProjectPreparationRevision(env)) unverified();
		const transport = createProjectCustomSamlTransport(
			project,
			authOrigin(env),
			env,
		);
		if (!(await transport.authorizeAcs(receiver, providerId))) unverified();
		const client = await database.connect();
		let discard = false;
		try {
			await client.query("BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY");
			const {
				rows: [record],
			} = await client.query<{
				id: string;
				providerId: string;
				issuer: string;
				domain: string;
				domainVerified: true;
				organizationId: string | null;
				samlConfig: string;
			}>(
				`SELECT id,"providerId",issuer,domain,"domainVerified","organizationId","samlConfig"
				 FROM "${schema}"."ssoProvider" WHERE "providerId"=$1
				 AND "domainVerified"=TRUE AND "samlConfig" IS NOT NULL AND "oidcConfig" IS NULL`,
				[providerId],
			);
			const samlConfig = readStoredSsoConfiguration(record?.samlConfig ?? null);
			if (!record || !samlConfig) unverified();
			const provider = { ...record, samlConfig };
			const selected = await configureProjectSamlTransport(provider, receiver, {
				allowEncrypted: true,
				customTransport: transport,
				validateAll: true,
			});
			if (selected.acs !== receiver) unverified();
			const proof = await verifyOwnedSaml(samlResponse, selected.configured);
			if (!proof.requestId || !proof.encryption) unverified();
			const requestKey = `saml-authn-request:${proof.requestId}`;
			const relayKey = `auth-state:${relayState}`;
			const replayKey = createHash("sha256")
				.update(`reserve:saml-used-assertion:${proof.assertionId}`)
				.digest("base64url");
			const { rows } = await client.query<{
				id: string;
				identifier: string;
				value: string;
				live: boolean;
			}>(
				`SELECT id,identifier,value,"expiresAt">clock_timestamp() AS live
				 FROM "${schema}"."verification"
				 WHERE (identifier=ANY($1::text[]) OR id=$2) AND EXISTS (
					SELECT 1 FROM "${schema}"."ssoProvider"
					WHERE id=$3 AND "providerId"=$4 AND issuer=$5 AND domain=$6
					AND "organizationId" IS NOT DISTINCT FROM $7 AND "domainVerified"=TRUE
					AND "samlConfig"=$8 AND "oidcConfig" IS NULL
				 ) LIMIT 3`,
				[
					[requestKey, relayKey],
					replayKey,
					record.id,
					providerId,
					record.issuer,
					record.domain,
					record.organizationId,
					record.samlConfig,
				],
			);
			const request = rows.find((row) => row.identifier === requestKey);
			const relay = rows.find((row) => row.identifier === relayKey);
			if (
				rows.length !== 2 ||
				rows.some((row) => row.id === replayKey) ||
				!request?.live ||
				!relay?.live
			)
				unverified();
			const authn = pendingRequest.parse(JSON.parse(request.value));
			const state = ssoStateSchema.parse(JSON.parse(relay.value));
			const now = Date.now();
			if (
				authn.id !== proof.requestId ||
				authn.providerId !== providerId ||
				authn.expiresAt <= now ||
				proof.replayExpiresAt <= now ||
				!sameSsoProvider(provider, authn.providerReference) ||
				state.expiresAt <= now ||
				state.oauthState !== relayState ||
				state.idTokenNonce !== undefined ||
				state.serverContext.allauthSamlRequestId !== undefined ||
				!sameSsoProvider(provider, state.serverContext.ssoProviderReference)
			)
				unverified();
			await client.query("COMMIT");
			return {
				kind: "observed-encrypted-saml-sample" as const,
				projectId: project.id,
				schemaName: schema,
				providerId,
				providerRecordId: record.id,
				legacyWriterRevision: revision,
				receiver,
				issuer: proof.issuer,
				configurationFingerprint: createHmac("sha256", secret)
					.update("allauth:encrypted-saml-evidence:v1\n")
					.update(JSON.stringify([project.id, receiver, record]))
					.digest("base64url"),
				observedAt: new Date(now).toISOString(),
				...proof.encryption,
			};
		} catch {
			try {
				await client.query("ROLLBACK");
			} catch {
				discard = true;
			}
			unverified();
		} finally {
			client.release(discard);
		}
	});
}

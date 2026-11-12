import { randomInt, randomUUID } from "node:crypto";
import { Resolver } from "node:dns/promises";
import { isIP } from "node:net";
import type { PoolClient } from "pg";
import {
	organizationFailure as failure,
	organizationJson as json,
} from "./owned-project-organization-response";
import type { StoredProjectSsoProvider } from "./owned-project-sso-projection";
import { ssoProviderId } from "./owned-project-sso-store";

const alphabet =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const dns = new Resolver({ timeout: 3000, tries: 2 });
const label = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
type DomainChallenge = { id: string; value: string; active: boolean };
export type ProjectSsoDomainProof = {
	provider: StoredProjectSsoProvider;
	domains: string[];
	identifier: string;
	challenge: DomainChallenge;
};

export function projectSsoDnsIdentifier(providerId: string) {
	return `_better-auth-token-${providerId}`;
}

export function projectSsoDomainNames(value: string) {
	const domains = [
		...new Set(
			value
				.split(",")
				.map((domain) => domain.trim().toLowerCase())
				.filter(Boolean),
		),
	];
	return domains.length &&
		domains.every((domain) => {
			const labels = domain.split(".");
			return (
				domain.length <= 253 &&
				labels.length > 1 &&
				!isIP(domain) &&
				labels.every((name) => label.test(name))
			);
		})
		? domains
		: undefined;
}

async function currentChallenge(client: PoolClient, identifier: string) {
	const result = await client.query<DomainChallenge>(
		`SELECT id,value,"expiresAt">statement_timestamp() AS active FROM "verification"
		WHERE identifier=$1 ORDER BY "createdAt" DESC,id DESC LIMIT 1 FOR UPDATE`,
		[identifier],
	);
	const challenge = result.rows[0];
	return challenge?.active ? challenge : undefined;
}

function verifyCandidate(provider: StoredProjectSsoProvider) {
	if (provider.domainVerified)
		return failure(409, "DOMAIN_VERIFIED", "Domain has already been verified");
	const identifier = projectSsoDnsIdentifier(provider.providerId);
	if (identifier.length > 63)
		return failure(
			400,
			"IDENTIFIER_TOO_LONG",
			"Verification identifier exceeds the DNS label limit of 63 characters",
		);
	if (
		!ssoProviderId.safeParse(provider.providerId).success ||
		!/^[a-zA-Z0-9_-]+$/.test(provider.providerId)
	)
		return failure(
			400,
			"INVALID_PROVIDER_ID",
			"Invalid DNS verification provider identifier.",
		);
	const domains = projectSsoDomainNames(provider.domain);
	if (!domains) return failure(400, "INVALID_DOMAIN", "Invalid domain");
	return { identifier, domains };
}

export async function requestProjectSsoDomainProof(
	client: PoolClient,
	provider: StoredProjectSsoProvider,
) {
	const candidate = verifyCandidate(provider);
	if (candidate instanceof Response) return candidate;
	const { identifier } = candidate;
	const current = await currentChallenge(client, identifier);
	if (current) return json({ domainVerificationToken: current.value }, 201);
	const token = Array.from(
		{ length: 24 },
		() => alphabet[randomInt(alphabet.length)],
	).join("");
	await client.query(
		`INSERT INTO "verification" (id,identifier,value,"expiresAt")
		VALUES ($1,$2,$3,statement_timestamp()+interval '7 days')`,
		[randomUUID(), identifier, token],
	);
	return json({ domainVerificationToken: token }, 201);
}

export async function readProjectSsoDomainProof(
	client: PoolClient,
	provider: StoredProjectSsoProvider,
): Promise<ProjectSsoDomainProof | Response> {
	const candidate = verifyCandidate(provider);
	if (candidate instanceof Response) return candidate;
	const challenge = await currentChallenge(client, candidate.identifier);
	if (!challenge)
		return failure(
			404,
			"NO_PENDING_VERIFICATION",
			"No pending domain verification exists",
		);
	return { provider, ...candidate, challenge };
}

export async function checkProjectSsoDomainDns(proof: ProjectSsoDomainProof) {
	for (const domain of proof.domains) {
		const records = await dns
			.resolveTxt(`${proof.identifier}.${domain}.`)
			.catch(() => []);
		const value = proof.challenge.value;
		if (
			!records.some((chunks) => {
				const record = chunks.join("").trim();
				return record === value || record === `${proof.identifier}=${value}`;
			})
		)
			return failure(
				502,
				"DOMAIN_VERIFICATION_FAILED",
				`Unable to verify domain ownership for ${domain}. Try again later`,
			);
	}
}

export async function verifyProjectSsoDomainProof(
	client: PoolClient,
	provider: StoredProjectSsoProvider,
	expected: ProjectSsoDomainProof,
) {
	const current = await readProjectSsoDomainProof(client, provider);
	if (current instanceof Response) return current;
	if (
		provider.id !== expected.provider.id ||
		provider.domain !== expected.provider.domain ||
		provider.organizationId !== expected.provider.organizationId ||
		current.challenge.id !== expected.challenge.id ||
		current.challenge.value !== expected.challenge.value
	)
		return failure(
			409,
			"SSO_PROVIDER_CHANGED",
			"SSO provider changed while domain verification was in progress. Reload the provider and try again",
		);
	await client.query(
		'UPDATE "ssoProvider" SET "domainVerified"=TRUE WHERE id=$1',
		[provider.id],
	);
}

import type { Pool } from "pg";
import type { LegacyMfaKeys } from "./legacy-mfa-record";
import { issuerJSON } from "./owned-project-issuer-http";
import { createOwnedProjectIssuerKeys } from "./owned-project-issuer-keys";
import { createOwnedProjectIssuerToken } from "./owned-project-issuer-token";

export function createOwnedProjectIssuer(options: {
	database: Pool;
	schemaName: string;
	issuer: string;
	keys: LegacyMfaKeys;
}) {
	const keyring = createOwnedProjectIssuerKeys(options);
	const token = createOwnedProjectIssuerToken(options);
	return async function dispatch(path: string, request: Request) {
		if (path === "/jwks" && request.method === "GET")
			return issuerJSON(await keyring.publicKeys());
		if (path === "/oauth2/token" && request.method === "POST")
			return token(request);
	};
}

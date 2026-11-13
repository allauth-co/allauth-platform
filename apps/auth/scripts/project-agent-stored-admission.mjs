function unsupported() {
	return new Error(
		"This project has stored Agent Auth outside the candidate scope.",
	);
}

function parseStoredJSON(value) {
	try {
		return JSON.parse(value);
	} catch {
		return value;
	}
}

const publicFields = new Set([
	"kty",
	"crv",
	"x",
	"kid",
	"alg",
	"use",
	"key_ops",
	"ext",
]);

/** Keep the stored key shape and Ed25519 import aligned with native Agent verification. */
async function checkStoredPublicKey(key, kid) {
	if (
		!key ||
		typeof key !== "object" ||
		Array.isArray(key) ||
		key.kty !== "OKP" ||
		key.crv !== "Ed25519" ||
		typeof key.x !== "string" ||
		!/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(key.x) ||
		(key.kid !== undefined &&
			(typeof key.kid !== "string" ||
				key.kid.length > 256 ||
				key.kid.includes("\0"))) ||
		(key.kid ?? null) !== kid ||
		Object.entries(key).some(
			([name, value]) =>
				!publicFields.has(name) ||
				!(
					typeof value === "string" ||
					typeof value === "boolean" ||
					(Array.isArray(value) &&
						value.every((item) => typeof item === "string"))
				),
		)
	)
		throw unsupported();
	try {
		const { alg: _algorithm, use: _usage, ...publicKey } = key;
		await crypto.subtle.importKey(
			"jwk",
			publicKey,
			"Ed25519",
			key.ext ?? true,
			key.key_ops ?? ["verify"],
		);
	} catch {
		throw unsupported();
	}
}

/** Check the same stored state in candidate readiness and under the writer switch lease. */
export async function assertStoredProjectAgentAdmission(client, schema) {
	if (!/^allauth_project_[a-f0-9]{32}$/.test(schema)) throw unsupported();
	const {
		rows: [state],
	} = await client.query(`
	 SELECT (
	  EXISTS (SELECT 1 FROM "${schema}"."agentCapabilityGrant") OR
	  EXISTS (
	   SELECT 1 FROM "${schema}"."agentHost" h WHERE
	    length(h.id)>512 OR h.id !~ '^[A-Za-z0-9_-]+$' OR h."userId" IS NULL OR h."jwksUrl" IS NOT NULL OR
	    h.status NOT IN ('active','pending_enrollment','revoked','rejected') OR
	    (h.status='active' AND nullif(h."publicKey",'') IS NULL) OR
	    (h.status='revoked' AND (h."publicKey" IS DISTINCT FROM '' OR h.kid IS NOT NULL)) OR
	    (h.status='pending_enrollment' AND (h."enrollmentTokenHash" IS NULL OR h."enrollmentTokenExpiresAt" IS NULL)) OR
	    ((h."enrollmentTokenHash" IS NULL) <> (h."enrollmentTokenExpiresAt" IS NULL)) OR
	    (h."enrollmentTokenHash" IS NOT NULL AND h."enrollmentTokenHash" !~ '^[A-Za-z0-9_-]{43}$') OR
	    EXISTS (SELECT 1 FROM "${schema}"."agentHost" other WHERE other.id<>h.id AND
	     (other.kid=h.id OR h.kid=other.id OR nullif(h.kid,'')=other.kid OR h."enrollmentTokenHash"=other."enrollmentTokenHash"))
	  ) OR
	  EXISTS (
	   SELECT 1 FROM "${schema}"."agent" a JOIN "${schema}"."agentHost" h ON h.id=a."hostId" WHERE
	    length(a.id)>512 OR a.id='host' OR a.id !~ '^[A-Za-z0-9_-]+$' OR a.mode<>'delegated' OR a."jwksUrl" IS NOT NULL OR
	    a.status NOT IN ('active','expired','pending','revoked','rejected') OR
	    (a."userId" IS NOT NULL AND a."userId" IS DISTINCT FROM h."userId") OR
	    (a.status IN ('active','expired') AND a."userId" IS NULL) OR
	    (a.status IN ('active','expired','pending') AND a."publicKey"='') OR
	    (a.status='revoked' AND (a."publicKey"<>'' OR a.kid IS NOT NULL)) OR
	    (h.status<>'active' AND a.status IN ('active','expired','pending'))
	  ) OR
	  EXISTS (
	   SELECT 1 FROM "${schema}"."approvalRequest" r
	   LEFT JOIN "${schema}"."agentHost" h ON h.id=r."hostId"
	   LEFT JOIN "${schema}"."agent" a ON a.id=r."agentId" WHERE
	    h.id IS NULL OR (a.id IS NOT NULL AND a."hostId" IS DISTINCT FROM h.id) OR
	    r.method NOT IN ('device_authorization','ciba') OR r.status NOT IN ('pending','approved','denied','expired') OR
	    nullif(btrim(r.capabilities),'') IS NOT NULL OR r.interval<>5 OR
	    r."clientNotificationToken" IS NOT NULL OR r."clientNotificationEndpoint" IS NOT NULL OR
	    (r."userId" IS NOT NULL AND r."userId" IS DISTINCT FROM h."userId") OR
	    (r.method='ciba' AND (r."userId" IS NULL OR r."deliveryMode" IS DISTINCT FROM 'poll' OR r."userCodeHash" IS NOT NULL)) OR
	    (r.method='device_authorization' AND (a.id IS NULL OR r."deliveryMode" IS NOT NULL OR
	     r."userCodeHash" IS NULL OR r."userCodeHash" !~ '^[A-Za-z0-9_-]{43}$'))
	  )
	 ) AS incompatible`);
	if (!state || state.incompatible) throw unsupported();
	const { rows } = await client.query(`
	 SELECT "publicKey",kid,"defaultCapabilities" AS budget,NULL::text AS metadata FROM "${schema}"."agentHost"
	 UNION ALL
	 SELECT "publicKey",kid,NULL::text AS budget,metadata FROM "${schema}"."agent"`);
	for (const { publicKey, kid, budget, metadata } of rows) {
		if (budget !== null) {
			const parsed = parseStoredJSON(budget);
			const values =
				typeof parsed === "string" ? parseStoredJSON(parsed) : parsed;
			if (!Array.isArray(values) || values.length !== 0) throw unsupported();
		}
		if (metadata !== null) {
			const parsed = parseStoredJSON(metadata);
			if (
				parsed !== null &&
				(typeof parsed !== "object" || Array.isArray(parsed))
			)
				throw unsupported();
		}
		if (!publicKey) {
			if (kid !== null) throw unsupported();
			continue;
		}
		await checkStoredPublicKey(parseStoredJSON(publicKey), kid);
	}
}

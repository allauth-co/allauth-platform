export const productionProjectEngineRevisionsSetting =
	"ALLAUTH_PROJECT_ENGINE_PRODUCTION_REVISIONS";
export const developmentProjectEngineRevisionsSetting =
	"ALLAUTH_PROJECT_ENGINE_DEVELOPMENT_REVISIONS";
export const encryptedSamlApprovalSetting =
	"ALLAUTH_PROJECT_ENGINE_ENCRYPTED_SAML_APPROVAL";
export const productionEncryptedSamlApprovalsSetting =
	"ALLAUTH_PROJECT_ENGINE_PRODUCTION_SAML_APPROVALS";
export const developmentEncryptedSamlApprovalsSetting =
	"ALLAUTH_PROJECT_ENGINE_DEVELOPMENT_SAML_APPROVALS";
export const projectEngineIdPattern =
	/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/;

/** @param {string | undefined} raw @param {"development" | "production"} scope @returns {Map<string, number>} */
export function readProjectEngineRevisions(
	raw,
	scope = "production",
) {
	const configured = raw?.trim();
	if (!configured) return new Map();
	const invalid = () =>
		new Error(`The ${scope} project preparation revisions are invalid.`);
	let revisions;
	try {
		revisions = JSON.parse(configured);
	} catch {
		throw invalid();
	}
	if (!revisions || typeof revisions !== "object" || Array.isArray(revisions))
		throw invalid();
	const entries = Object.entries(revisions);
	for (const [id, revision] of entries) {
		if (
			!projectEngineIdPattern.test(id) ||
			typeof revision !== "number" ||
			!Number.isInteger(revision) ||
			revision < 0 ||
			revision > 2147483647
		)
			throw invalid();
	}
	return new Map(entries);
}

/** @param {string | undefined} raw @param {string} projectId */
export function readProjectEngineApprovalValue(raw, projectId) {
	const configured = raw?.trim();
	if (!configured) return "";
	const invalid = () => new Error("The project approvals are invalid.");
	let approvals;
	try {
		approvals = JSON.parse(configured);
	} catch {
		throw invalid();
	}
	if (!approvals || typeof approvals !== "object" || Array.isArray(approvals))
		throw invalid();
	for (const [id, approval] of Object.entries(approvals)) {
		if (
			!projectEngineIdPattern.test(id) ||
			!approval ||
			typeof approval !== "object" ||
			Array.isArray(approval)
		)
			throw invalid();
	}
	return Object.hasOwn(approvals, projectId)
		? JSON.stringify(approvals[projectId])
		: "";
}

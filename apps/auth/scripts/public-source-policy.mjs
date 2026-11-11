import { createHash } from "node:crypto";
import path from "node:path";

const operationalDocuments = new Set([
	"CLOUDFLARE_SETUP.md", "design-qa.md", "apps/auth/design-qa.md",
	"apps/auth/SESSION_INTROSPECTION_VALIDATION.md", "apps/auth/docs/clerk-reference-review.md",
	"apps/auth/docs/review-2026-10-28-feature-completeness.md",
]);
const upstreamPublicFixtures = new Map([
	["test/fixtures/cert.pem", "f2aeb0177a5f8bbe193e185dce1998442df56e1dfb9bec73fe5a3f5cc12368a5"],
	["test/fixtures/key.pem", "a3ed8d8d01d1ed94545292ecc8283ae67f9bf5dba50bbe02b2990d147163c852"],
	["packages/sso/src/saml.test.ts", "080effbfe5b24dc5165012b1269bbad2421b1336505f7d8beab457bf0e2519f2"],
	["packages/sso/src/saml/assertions.test.ts", "f82ef6a5aa370218ffae2ff2da06195dd2486c7bf386fe811faefb73098a95d6"],
]);

/** Keep product implementations and tests while excluding private deployment records and generated material. */
export function publicSourceExclusion(name) {
	if (/(^|\/)(?:node_modules|\.git|\.secrets|output|\.next|\.open-next|\.wrangler|coverage|test-results|playwright-report|certificates)(?:\/|$)/.test(name)) return "private or generated directory";
	if (/(^|\/)(?:\.env(?:[./]|$)|\.dev\.vars(?:[./]|$))/.test(name) && !name.endsWith(".env.example")) return "environment credentials";
	if (/\.(?:pem|key|log|tsbuildinfo)$/.test(name) && !upstreamPublicFixtures.has(name)) return "local credential or generated file";
	if (name.startsWith("apps/auth/releases/") || name.startsWith("apps/auth/release-receipts/")) return "private operational release evidence";
	if (operationalDocuments.has(name)) return "private operational review or deployment record";
	if (name === "apps/auth/README.md") return "operational diary replaced by public service guide";
	if (name.startsWith(".github/workflows/") && name !== ".github/workflows/allauth-platform-ci.yml") return "upstream-only automation; public AllAuth CI is separate";
	if (name.startsWith(".github/ISSUE_TEMPLATE/") || name === ".github/config.yml") return "upstream issue automation";
	return undefined;
}

function section(text, heading, replacement) {
	const start = text.indexOf(heading);
	if (start < 0) return text;
	const next = text.indexOf("\n## ", start + heading.length);
	return text.slice(0, start) + replacement + (next < 0 ? "" : text.slice(next + 1));
}

function fixtureUuid(value) {
	const hex = createHash("sha256").update(`allauth-public-fixture:${value}`).digest("hex");
	return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-4${hex.slice(13, 16)}-8${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
}

/** Rewrite examples and operational documentation only; ordinary product code remains byte-for-byte source. */
export function publicSourceText(name, original) {
	let text = original;
	if (name === "README.md") text = text.replaceAll("apps/auth/README.public.md", "apps/auth/README.md");
	if (name === "apps/auth/INTEGRATION.md") text = section(text, "## Hosting and operations", "## Hosting and operations\n\nRun the standalone Node image with your own PostgreSQL connection and provider configuration. See the [self-hosting guide](../../docs/SELF_HOSTING.md) for deployment, migrations, backups and recovery. Application integrations use their scoped client/proxy credentials, never database or operator credentials.\n\n");
	if (name === "apps/auth/docs/hosted-domains.md") {
		text = text.replace(/^Provider read-back on .*\n?/m, "");
		text = text.replaceAll("allauth-production.up.railway.app", "your-service.up.railway.app");
	}
	if (name === "docs/content/docs/integrations/allauth-owned-profile-photos.mdx") {
		text = text.replace(/^The compatible runtime and private storage are deployed\.[\s\S]*?(?=\n## )/, "Owned profile-photo availability is an opt-in capability. Keep native photo selection hidden unless both `profileImageUpload` and `profileImageOwnershipAndDeletion` are true for the selected environment. Name changes, manual HTTPS image URLs and removing a profile image remain independent controls.\n");
		text = section(text, "## Recorded deployment checkpoint", "");
		text = section(text, "## Operator targets", "## Configure your own environment\n\nProvision your own private owned-avatar bucket and binding. Keep project selection empty and `OWNED_AVATAR_PRIVATE_STORAGE=false` until public-access and cache checks pass. Configure the same independent server-only avatar secret on your asset Worker, app and cleanup service. Start cleanup with scoped heartbeat checks, then opt in only the reviewed immutable project IDs. Keep the compatible Worker, migrations, tombstones and cleanup process until all registered jobs drain; clearing an opt-in is not an erasure operation.\n\n");
		text = text.replace("The recorded checkpoint above identifies the existing environment's completed setup; do not recreate its bucket or rotate a secret merely to repeat this runbook.", "Use resources and credentials owned by your deployment; do not reuse a hosted environment's settings.");
	}
	const fixture = /\.(?:test|spec)\.[cm]?[jt]sx?$/.test(name) && name !== "apps/auth/scripts/public-source-policy.test.mjs";
	const documentation = /\.mdx?$/.test(name);
	if (fixture || documentation) {
		const customerExample = /surveypeach|crowdtree|crowdtr\.ee|startupcircle|Startup Circle/i.test(text);
		for (const [value, replacement] of [
			["surveypeach.com", "exampleapp.example"], ["SURVEYPEACH", "EXAMPLEAPP"], ["SurveyPeach", "ExampleApp"], ["surveypeach", "exampleapp"],
			["crowdtr.ee", "nativeapp.example"], ["CROWDTree", "NATIVEAPP"], ["CROWDTREE", "NATIVEAPP"], ["CrowdTree", "NativeApp"], ["crowdtree", "nativeapp"],
			["Startup Circle", "Example Community"], ["STARTUPCIRCLE", "COMMUNITYAPP"], ["startupcircle", "communityapp"],
		]) text = text.replaceAll(value, replacement);
		if (fixture && customerExample) {
			text = text.replaceAll("JWJ4JYF8E6", "TESTTEAM01");
			text = text.replace(/\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b/gi, fixtureUuid);
		}
	}
	if (documentation) text = text.replace(/\[([^\]]+)\]\(([^)]+)\)/g, (link, label, target) => {
		if (/^(?:[a-z]+:|#|\/)/i.test(target)) return link;
		const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(name), target.split("#")[0]));
		return resolved !== "apps/auth/README.md" && publicSourceExclusion(resolved) ? `${label} (private operational evidence)` : link;
	});
	return text;
}

/** Public Worker examples never retain a provider account, live origin, route or verified-private flag. */
export function publicWorkerConfiguration(name, original) {
	if (!/^apps\/auth\/wrangler(?:\.(?:assets|domains))?\.jsonc$/.test(name)) return original;
	const config = JSON.parse(new TextDecoder().decode(original));
	delete config.account_id; delete config.routes;
	if (config.vars) {
		for (const [key, value] of Object.entries(config.vars)) if (typeof value === "string") config.vars[key] = value.replaceAll("allauth.co", "auth.example.com").replaceAll("tom@onsavii.com", "admin@example.com");
		if ("ALLAUTH_ORIGIN" in config.vars) config.vars.ALLAUTH_ORIGIN = "https://your-service.up.railway.app";
		if ("OWNED_AVATAR_PRIVATE_STORAGE" in config.vars) config.vars.OWNED_AVATAR_PRIVATE_STORAGE = "false";
	}
	if (config.send_email) for (const sender of config.send_email) sender.allowed_sender_addresses = ["security@example.com"];
	if (config.r2_buckets) for (const bucket of config.r2_buckets) if (!bucket.bucket_name.startsWith("my-")) bucket.bucket_name = `my-${bucket.bucket_name}`;
	config.workers_dev = false;
	return new TextEncoder().encode(`${JSON.stringify(config, null, 2)}\n`);
}

/** Emit only finding kind/line metadata, never matched credential text. */
export function publicCredentialFindings(source, text) {
	const expectedFixture = upstreamPublicFixtures.get(source);
	if (expectedFixture && createHash("sha256").update(text).digest("hex") === expectedFixture) return [];
	const patterns = [
		["Stripe secret", /(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,}/g],
		["Stripe webhook secret", /whsec_[A-Za-z0-9]{24,}/g],
		["OpenAI credential", /sk-(?:proj|svcacct)-[A-Za-z0-9_-]{30,}/g],
		["GitHub token", /(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})/g],
		["AWS access key", /(?:AKIA|ASIA)[A-Z0-9]{16}/g],
		["Slack credential", /xox[baprs]-[A-Za-z0-9-]{24,}/g],
		["Private key", /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----\r?\n[A-Za-z0-9+/=\r\n]{80,}-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g],
	];
	return patterns.flatMap(([kind, expression]) => [...text.matchAll(expression)].map(match => ({ path: source, line: text.slice(0, match.index).split("\n").length, kind })));
}

// cspell:words organisation authorisation
import type {
	AnnouncedRelease,
	AnnouncedSdkRelease,
	PlatformRelease,
	SdkRelease,
} from "./catalog-types";
import { sdkReleaseHistory } from "./history";

export type {
	AnnouncedPlatformRelease,
	AnnouncedRelease,
	AnnouncedSdkRelease,
	HistoricalPlatformRelease,
	HistoricalSdkRelease,
	PlatformRelease,
	ReleaseProvenance,
	SdkRelease,
} from "./catalog-types";

/** Only additive fixes belong in this compatible release feed. Never silently upgrade customer packages. */
export const sdkReleases: readonly [AnnouncedSdkRelease, ...SdkRelease[]] = [
	{
		title: "AllAuth React SDK 1.4.6: in-app two-factor verification",
		summary:
			"Applications can explicitly display the shared AllAuth authenticator or backup-code challenge inside their own sign-in screen. AllAuth continues to verify the factor and resume native OAuth; existing integrations retain hosted verification unless they upgrade and opt in.",
		notes: [
			'Enable brokerTwoFactor: { signInUrl: "/sign-in" } on the standard Next.js /api/allauth proxy after the public local sign-in page renders the matching portable SDK SignIn component. The matching AllAuth service must be deployed; older services keep hosted MFA.',
			"Expiring handoffs are bound to the registered application, exact origin and initiating browser. Central session cookies stay on AllAuth, and native single-use challenges, attempt limits, lockout, rate limiting, OAuth state and PKCE remain authoritative.",
			"After verification, a short browser redirect restores the AllAuth session and resumes native OAuth. Required consent may still display its hosted screen. Authenticator and backup codes are supported; custom proxy base paths and the optional Better Auth UI registry wrapper retain hosted MFA.",
			"Existing application-account MFA, direct providers, cookies and signed requests remain compatible. Customer upgrades are explicit, every previous archive is retained unchanged, and no database migration is required.",
		],
		sourceUrl:
			"https://github.com/thegarty/allauth-sdk/tree/v1.4.6/packages/react",
		provenance: [
			{
				kind: "release",
				details:
					"Immutable GitHub release v1.4.6 was published at 2026-11-06T21:30:55Z from SDK-only source 53081928e161e41cf88704303f3aa879b32b720d. Its exact archive and checksum asset digests match the reviewed candidate; the release workflow passed all 19 archive/tag checks, 18 public regressions, source scanning and strict typechecking before publication. Matching platform deployment and production browser acceptance are recorded separately.",
				files: [
					"broker-two-factor-server.ts",
					"next.ts",
					"react.tsx",
					"README.md",
				],
			},
		],
		sha256: "3e19d53f8fd90267b525412cdbeebe9182180608d8621777b81b6dfc6d1e69b5",
		upgradeUrl: "https://allauth.co/sdk/quickstart",
		changelogUrl: "https://allauth.co/releases/sdk-1-4-6",
		downloadUrl: "https://allauth.co/sdk/allauth-react-1.4.6.tgz",
		version: "1.4.6",
		kind: "sdk",
		id: "sdk-1.4.6",
		slug: "sdk-1-4-6",
		announce: true,
		dateConfidence: "known",
		compatibility: "backward-compatible",
		publishedAt: "2026-11-06T21:30:55Z",
	},
	{
		kind: "sdk",
		id: "sdk-1.4.5",
		slug: "sdk-1-4-5",
		announce: false,
		dateConfidence: "known",
		version: "1.4.5",
		title: "AllAuth React SDK 1.4.5: isolated application support",
		summary:
			"Opt-in application-initiated support can run on a separate application hostname while ordinary administrator tabs retain their sign-in. The proxy preserves safe native actor/session context and validates the exact application return destination. Existing console support, cookies, signed transport and sign-in remain compatible.",
		notes: [
			"Add the exact applicationReturnUrl to the support proxy options when enabling application-initiated support on an isolated hostname. The matching service must explicitly enable delegation and register the separate callback.",
			"Safe actor kind/session, application audit ID and context are preserved through support status. Native session credentials remain in HttpOnly cookies, and support cleanup returns only the configured main-app administrator destination.",
			"The host must enforce its own current administrator/context checks on business and native proxy requests, block ordinary auth/admin flows on the support hostname and restrict native writes there to support-stop. Existing integrations remain disabled until explicitly configured; no customer upgrade or credential change is automatic.",
		],
		sourceUrl:
			"https://github.com/thegarty/allauth-sdk/tree/v1.4.5/packages/react",
		provenance: [
			{
				kind: "release",
				details:
					"Immutable public SDK source/tag v1.4.5 and exact archive/checksum assets were verified on GitHub. Local isolated-origin native support, SDK source/archive parity, retained-client transport and Vite-style ES2020 consumer typechecks passed before publication. Matching service rollout is recorded separately.",
				files: ["support-server.ts", "support-banner.tsx", "README.md"],
			},
		],
		publishedAt: "2026-11-06T01:54:54Z",
		compatibility: "historical",
		upgradeUrl: "https://allauth.co/sdk/quickstart",
		changelogUrl: "https://allauth.co/releases/sdk-1-4-5",
		downloadUrl: "https://allauth.co/sdk/allauth-react-1.4.5.tgz",
		sha256: "63c5fc7cdf264f92f065d800ef0b6ea53650ccb5f5d3232ac1ff6633d6e5c397",
	},
	{
		kind: "sdk",
		id: "sdk-1.4.4",
		slug: "sdk-1-4-4",
		announce: false,
		dateConfidence: "known",
		version: "1.4.4",
		title: "AllAuth React SDK 1.4.4 is available",
		summary:
			"The Next.js application proxy now forwards Retry-After from AllAuth so applications can honor a temporary session-check rate refusal. HTTP status, JSON error codes and cookie headers remain intact. Existing integrations receive the service-side session-check resilience fix without an SDK upgrade; update your pinned package and rebuild to forward the response header to browsers.",
		notes: [
			"The Next.js proxy forwards Retry-After unchanged for both JSON and streamed responses, including numeric delays and HTTP dates.",
			"HTTP 429 status, the service's stable error code, separate Set-Cookie headers and existing request-signature behavior remain compatible.",
			"No automatic retries, customer dependency upgrades, credential changes or completed session-result caching are introduced. Existing SDK versions continue to authenticate with the updated service.",
		],
		sourceUrl:
			"https://github.com/thegarty/allauth-sdk/tree/v1.4.4/packages/react",
		provenance: [
			{
				kind: "release",
				details:
					"Failing-first proxy regressions cover numeric and HTTP-date Retry-After values, JSON and streamed HTTP 429 replies, cookies and credential-header boundaries. Focused SDK and archived-client compatibility checks passed before publication.",
				files: ["next.ts", "README.md"],
			},
		],
		publishedAt: "2026-10-30T02:55:59Z",
		compatibility: "historical",
		upgradeUrl: "https://allauth.co/sdk/quickstart",
		changelogUrl: "https://allauth.co/releases/sdk-1-4-4",
		downloadUrl: "https://allauth.co/sdk/allauth-react-1.4.4.tgz",
		sha256: "bf3896199f789253fbaf0acb6a8c7f8975912bf8bec1118c54668c67ac9896ee",
	},
	{
		kind: "sdk",
		id: "sdk-1.4.3",
		slug: "sdk-1-4-3",
		announce: false,
		dateConfidence: "known",
		version: "1.4.3",
		title: "AllAuth React SDK 1.4.3 is available",
		summary:
			"Organisation permission and slug checks no longer reload the active organisation. The organisation manager verifies fully granted permissions in one request, reducing delays and request-limit errors. Existing APIs, sign-in flows and organisation permissions remain compatible. Upgrade your pinned SDK package and rebuild your application when convenient.",
		notes: [
			"Read-only organisation permission and slug checks no longer invalidate active organisation hooks.",
			"Organisation managers with all required permissions use one combined native permission check; delegated permissions retain individual verification.",
			"Optional SDK-version reports support advisory dashboard update notices without requiring access to customer source code.",
		],
		sourceUrl:
			"https://github.com/thegarty/allauth-sdk/tree/v1.4.3/packages/react",
		provenance: [
			{
				kind: "release",
				details:
					"Verified request-budget regression tests, package parity and the immutable 1.4.3 archive support this announcement.",
				files: [
					"client.ts",
					"organization-profile.tsx",
					"next.ts",
					"README.md",
				],
			},
		],
		publishedAt: "2026-10-30T01:14:16Z",
		compatibility: "historical",
		upgradeUrl: "https://allauth.co/sdk/quickstart",
		changelogUrl: "https://allauth.co/releases/sdk-1-4-3",
		downloadUrl: "https://allauth.co/sdk/allauth-react-1.4.3.tgz",
		sha256: "1945650e97e2ad364e7be36f87d276c58544c3ed2e589ce187aa7a4489c96178",
	},
	...sdkReleaseHistory,
];

/** New platform announcements and retained public history share permanent release pages. */
export const platformReleases: readonly PlatformRelease[] = [
	{
		kind: "platform",
		id: "platform-commercial-preview-2026-11-11",
		slug: "platform-commercial-preview-2026-11-11",
		title: "Commercial plans and self-hosting preview",
		summary: "Workspace billing infrastructure, clear Free and Pro plans, competitor comparisons and a complete self-hosting pathway are prepared. Hosted checkout and new plan limits remain disabled until live Stripe activation and tax setup are verified.",
		notes: [
			"The planned Pro offer is US$9.99 per workspace per month plus applicable tax, covering its applications and environments. It removes AllAuth attribution and includes unlimited customer-organisation members and support impersonations under fair use. Free includes 20 members per customer organisation and five monthly impersonations shared across the workspace in UTC.",
			"This preview does not start charging existing workspaces or activate Free limits. Launch requires an explicit operator rollout after live payment readiness. Existing memberships and ordinary sessions are preserved on downgrade; cancellation retains Pro through the paid period and failed renewals receive one seven-day recovery window.",
			"Billing uses server-owned Stripe Checkout and Customer Portal sessions, signature-verified durable webhook processing, payment-confirmed local entitlements and independent reconciliation. Authentication never waits for Stripe. No customer SDK upgrade is required and all retained SDK archives remain unchanged.",
			"Explicit self-hosted mode enables all product capabilities without Stripe. Docker Compose, initial-administrator setup and backup/upgrade guidance are included. The complete AllAuth platform source is published under MIT in a clean public repository with upstream and third-party notices retained; private operational history is excluded.",
		],
		publishedAt: "2026-11-11T00:34:00.000Z",
		dateConfidence: "known",
		compatibility: "platform-update",
		changelogUrl: "https://allauth.co/releases/platform-commercial-preview-2026-11-11",
		sourceUrl: "https://github.com/thegarty/allauth-platform/tree/platform-commercial-preview-2026-11-11",
		announce: false,
		provenance: [{ kind: "release", details: "Preview notes prepared on 11 November 2026 after local billing, entitlement, PostgreSQL concurrency, SDK-compatibility, typecheck and real Stripe sandbox checks. Hosted checkout and enforcement are explicitly disabled for the infrastructure rollout. Production deployment, source publication and live-launch evidence are recorded separately in the release receipt; this preview does not claim those outcomes.", files: ["lib/billing", "migrations/017-workspace-billing.sql", "migrations/018-commercial-entitlements.sql", "compose.self-host.yml", "docs/SELF_HOSTING.md"] }],
	},
	{
		kind: "platform",
		id: "platform-in-app-mfa-2026-11-07",
		slug: "platform-in-app-mfa-2026-11-07",
		title: "In-app two-factor verification for shared sign-in",
		summary:
			"Opted-in applications can collect the central AllAuth authenticator or backup code in their own sign-in screen, while native verification and OAuth remain authoritative. Existing integrations keep the hosted challenge.",
		notes: [
			"Requires SDK 1.4.6 and the explicit brokerTwoFactor server option with the matching portable SignIn component. Existing customer packages, hosted integrations and direct application-owned providers are not changed automatically.",
			"The encrypted five-minute handoff is bound to the registered broker, exact app origin and an initiating-browser secret. Native factor consumption, attempt budgets, lockout, rate limiting and OAuth state/PKCE remain enforced; central cookies are never copied into the application.",
			"JSON-based primary sign-ins continue from the hosted page only after checking the native signed live pending cookie and signed authorization query. Missing, forged, expired, tampered or unsupported context retains the hosted flow.",
			"A one-use completion receipt restores the platform session only in the original browser, then resumes native OAuth and any required consent. The receipt lasts one minute; the native OAuth request expiry remains authoritative. No database migration is needed.",
		],
		publishedAt: "2026-11-06T21:40:15.280Z",
		dateConfidence: "known",
		compatibility: "platform-update",
		changelogUrl: "https://allauth.co/releases/platform-in-app-mfa-2026-11-07",
		sourceUrl: null,
		announce: true,
		provenance: [
			{
				kind: "deployment",
				details:
					"The initial in-app broker MFA service reached Railway SUCCESS in deployment 91002ca2-b1ce-46b2-bbde-95e0ca47c6ea at 2026-11-06T21:40:15.280Z from merge 4d6fcf973eaa24b74cf3ebd7fe63b3766cc2e301. Production smoke testing then identified the JSON-primary hosted-page continuation gap; a focused regression reproduced it on the original service. The continuation now requires a signed unexpired native pending cookie and signed broker query. Final corrected deployment and browser acceptance are recorded separately in the release receipt.",
				files: [
					"broker-two-factor.ts",
					"mfa.ts",
					"two-factor/page.tsx",
					"broker-login.test.ts",
					"allauth-in-app-two-factor.mdx",
				],
			},
		],
	},
	{
		kind: "platform",
		id: "platform-support-cleanup-2026-11-06",
		slug: "platform-support-cleanup-2026-11-06",
		title: "Acknowledge already-ended application support sessions",
		summary:
			"Allows an application to finish cleanup after an earlier native support session and its short-lived binding have both disappeared. The fallback acknowledges absence without granting authority over any existing session.",
		notes: [
			"The absence-only acknowledgement requires a current application support registration, exact signed main-app/project transport and a live ordinary native actor. It performs no session mutation and discloses no additional session identifiers.",
			"Any existing native session still requires the complete retained actor/session/audit proof before it can be revoked. Missing or forged transport, an unrelated origin, no live actor and disabled delegation remain denied.",
			"Existing bound cleanup, 24-hour receipts, ordinary sign-in and immutable SDK 1.4.5 remain compatible.",
		],
		compatibility: "platform-update",
		publishedAt: "2026-11-06T03:30:00.701Z",
		dateConfidence: "known",
		sourceUrl: null,
		changelogUrl:
			"https://allauth.co/releases/platform-support-cleanup-2026-11-06",
		provenance: [
			{
				kind: "release",
				details:
					"A failing-first fixture reproduced the expired-binding/already-deleted-session cleanup error. Forty-five support/introspection regressions pass, including repeat-safe absence acknowledgement, preserved ordinary actor sign-in, unsigned/cookieless/wrong-origin/disabled-policy denial and refusal to touch existing sessions lacking their full binding. Service typecheck, production build and immutable SDK checks passed before deployment.",
				files: [
					"support-plugin.ts",
					"support-plugin.test.ts",
					"allauth-support-sessions.mdx",
				],
			},
			{
				kind: "deployment",
				details:
					"Railway deployment d559b8a9-f7fe-4a92-b36e-ce5eace30105 of source 5485ca2966c9cb1f58b5493dddce9fd05ed2eb36 reached SUCCESS on 2026-11-06T03:30:00.701Z. Service readiness, anonymous native session response and an existing verified management session passed after deployment. Application browser cleanup acceptance is recorded separately.",
				files: ["support-plugin.ts", "support-plugin.test.ts"],
			},
		],
		announce: true,
	},
	{
		kind: "platform",
		id: "platform-support-introspection-2026-11-06",
		slug: "platform-support-introspection-2026-11-06",
		title: "Preserve support proof during optimized session checks",
		summary:
			"Fixes application-initiated support sessions ending immediately after handoff when the optimized server session-check path omitted the original verified request context.",
		notes: [
			"Optimized native session checks retain the verified signed request so support-origin, integration-version and actor/session proofs are checked by the same native hooks as HTTP requests.",
			"Ordinary application actors remain ordinary users; the fix grants no native administrator authority and retains missing/forged-origin denial, native expiry, original-session revocation, safe status and cleanup.",
			"The published SDK 1.4.5 archive and all existing SDK/cookie/request contracts are unchanged. Applications need no dependency upgrade for this service correction.",
		],
		compatibility: "platform-update",
		publishedAt: "2026-11-06T03:02:26.177Z",
		dateConfidence: "known",
		sourceUrl: null,
		changelogUrl:
			"https://allauth.co/releases/platform-support-introspection-2026-11-06",
		provenance: [
			{
				kind: "release",
				details:
					"An actual SDK handoff routed through optimized native ingress reproduced immediate null-session failure before the patch. Focused native support/session suites, forged and missing-origin denial, safe status/cleanup, service typecheck, production build and immutable SDK checks passed before deployment.",
				files: [
					"session-introspection.ts",
					"route.ts",
					"support-plugin.test.ts",
				],
			},
			{
				kind: "deployment",
				details:
					"Railway deployment 6d1ba4bc-f048-4341-9e2e-65c02b580825 of source 1fdefce701a2675f754940dd944f6f272b55d9e9 reached SUCCESS on 2026-11-06T03:02:26.177Z. Service readiness, anonymous native session response and an existing verified management session passed after deployment. Browser handoff acceptance is recorded separately.",
				files: [
					"session-introspection.ts",
					"route.ts",
					"support-plugin.test.ts",
				],
			},
		],
		announce: true,
	},
	{
		kind: "platform",
		id: "platform-application-backends-2026-11-06",
		slug: "platform-application-backends-2026-11-06",
		announce: true,
		dateConfidence: "known",
		title: "Scoped backend directory and native application support",
		summary:
			"Adds explicit environment-scoped backend directory reads, silent pending-invitation migration and native application-initiated support without installing workspace administrator sessions in an application.",
		notes: [
			"Separate expiring directory:read credentials are issued once, stored as hashes and revocable immediately. Bounded user, organisation, membership and role reads grant no session, mutation or management authority.",
			"Verified backend directory credentials use shared admission of 20 reads per second with 120 immediate burst credits per project/key. Invalid credentials keep existing request protection; no completed authorization result is cached.",
			"Management-only pending invitation import preserves original recipients, roles, inviters and expiry with immutable source provenance. Dry runs and repeat-safe applied results send no email; manual resend remains explicit.",
			"Application support requires opt-in isolated callback and fixed canonical-app authorisation. Original native actor/session proof and one-use PKCE handoff bound target sessions to 15 minutes. Applications must enforce their own current administrator/context roles.",
			"The MCP login prompt explicitly separates the MFA method choice from hidden code entry and permits bounded corrections to a mistaken method choice before exchanging the grant.",
		],
		publishedAt: "2026-11-06T02:24:34.917Z",
		compatibility: "platform-update",
		sourceUrl: null,
		changelogUrl:
			"https://allauth.co/releases/platform-application-backends-2026-11-06",
		provenance: [
			{
				kind: "deployment",
				details:
					"Railway deployment 05684a31-e96e-47d5-9dfe-a539b212ab65 of source a40320c4c21918f3e48334382ff18eeac160a2df reached SUCCESS on 2026-11-06T02:24:34.917Z after applying the included migrations. Public service health, SDK 1.4.5 downloads and the existing verified root-management session were checked separately. Individual application opt-in and production migration acceptance remain integration rollout work.",
				files: [
					"backend-credentials.ts",
					"service-directory.ts",
					"service-directory-transport.ts",
					"invitation-import.ts",
					"support-plugin.ts",
					"login.ts",
				],
			},
		],
	},
	{
		kind: "platform",
		id: "platform-session-introspection-2026-10-30",
		slug: "platform-session-introspection-2026-10-30",
		title: "Resilient session checks for existing integrations",
		summary:
			"Verified application-server session checks gain shared sustained and burst admission, bounded overlap combining and clear diagnostics. Existing SDK integrations receive the service-side fix without upgrading, while live session verification and revocation remain authoritative.",
		notes: [
			"Verified signed session checks use continuous admission of 20 checks per second per project/session with 120 immediate burst credits, shared through PostgreSQL across service replicas.",
			"Each caller verifies its request and consumes its own admission. Identical checks can combine while admission is pending; each group closes before the live native lookup starts. Responses and cookie headers are independent.",
			"No completed authentication result is cached. New arrivals cannot join an older authority read, and failures do not grant authentication. Password, MFA, recovery and invalid-request protections retain their existing paths.",
			"HTTP 429 retains Retry-After and adds ALLAUTH_SESSION_CHECK_RATE_LIMITED. Credential-free diagnostics distinguish rate refusal, invalid sessions, verification failure and service failure.",
			"The unchanged 1.0.0 proxy passed local multi-user and two-replica prevention tests, including 384 clustered checks and 2,640 checks over a full sustained minute. These fixtures are compatibility evidence, not a production capacity claim.",
		],
		publishedAt: "2026-10-30T02:44:35Z",
		dateConfidence: "known",
		compatibility: "platform-update",
		announce: false,
		sourceUrl: null,
		changelogUrl:
			"https://allauth.co/releases/platform-session-introspection-2026-10-30",
		provenance: [
			{
				kind: "release",
				details:
					"Service-side admission, coordination, revocation, isolation, failure-recovery and unchanged-archive compatibility regressions passed locally. Deployment and production integration verification are recorded separately in the release receipt.",
				files: [
					"session-introspection.ts",
					"session-introspection-admission.ts",
					"session-check-coordinator.ts",
					"SESSION_INTROSPECTION_VALIDATION.md",
				],
			},
		],
	},
	{
		kind: "platform",
		id: "platform-release-notifications-2026-10-30",
		slug: "platform-release-notifications-2026-10-30",
		title: "Release notifications and compatibility safeguards",
		summary:
			"Adds an account-wide release notification centre, optional update emails and compatibility checks for immutable SDK downloads.",
		notes: [
			"Adds an account-wide unread notification centre with persistent read state and release email preferences.",
			"Verified workspace owners and admins can receive release alerts through durable jobs with retries, eligibility checks and opt-out handling.",
			"Optional SDK-version reports provide advisory update information without granting access or requiring a customer's repository.",
			"Immutable archive checks and legacy proxy compatibility gates protect previously published SDK packages and existing integrations.",
		],
		publishedAt: "2026-10-30T01:14:16Z",
		dateConfidence: "known",
		compatibility: "platform-update",
		announce: false,
		sourceUrl: null,
		changelogUrl:
			"https://allauth.co/releases/platform-release-notifications-2026-10-30",
		provenance: [
			{
				kind: "deployment",
				details:
					"Verified service deployment, authenticated dashboard/API checks, public archive checks and update email acceptance checks support this release record.",
				files: [],
			},
		],
	},
];

/** Historical archive backfills never create unread announcements or email jobs. */
export function activeSdkAnnouncements(
	now = new Date(),
): AnnouncedSdkRelease[] {
	return sdkReleases.filter(
		(release): release is AnnouncedSdkRelease =>
			release.announce && Date.parse(release.publishedAt) <= now.getTime(),
	);
}

/** Explicitly announced SDK and hosted-platform releases share account read state and email delivery. */
export function activeReleaseAnnouncements(
	now = new Date(),
): AnnouncedRelease[] {
	return [...sdkReleases, ...platformReleases]
		.filter(
			(release): release is AnnouncedRelease =>
				release.announce && Date.parse(release.publishedAt) <= now.getTime(),
		)
		.sort(
			(left, right) =>
				Date.parse(right.publishedAt) - Date.parse(left.publishedAt) ||
				left.id.localeCompare(right.id),
		);
}

/** Advisory version strings never participate in authentication or authorization. */
export function normalizedSdkVersion(
	value: string | undefined | null,
): string | null {
	return typeof value === "string" &&
		value.length <= 64 &&
		!/\s/.test(value) &&
		/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/.test(
			value,
		)
		? value
		: null;
}

/** Unknown clients remain unknown; a release notification must not suggest downgrading a newer SDK. */
export function sdkUpdateAvailable(
	observed: string | null,
	latest: string,
): boolean | null {
	if (
		!observed ||
		!normalizedSdkVersion(observed) ||
		!normalizedSdkVersion(latest)
	)
		return null;
	const [leftCore, leftPre] = observed.split("-", 2),
		[rightCore, rightPre] = latest.split("-", 2);
	const left = leftCore.split(".").map(Number),
		right = rightCore.split(".").map(Number);
	for (let index = 0; index < 3; index++) {
		if (left[index] !== right[index]) return left[index] < right[index];
	}
	return Boolean(leftPre && !rightPre);
}

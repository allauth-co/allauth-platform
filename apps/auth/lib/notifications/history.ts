import integrity from "../../public/sdk/integrity.json";
import type { HistoricalSdkRelease } from "./catalog-types";

function archive(version: string, title: string, summary: string, notes: string[], files: string[], previousVersion?: string): HistoricalSdkRelease {
	const filename = `allauth-react-${version}.tgz` as keyof typeof integrity;
	const sha256 = integrity[filename];
	if (!sha256) throw new Error("Release history must reference an allowlisted immutable SDK archive.");
	const slug = `sdk-${version.replaceAll(".", "-")}`;
	return {
		kind: "sdk", id: `sdk-${version}`, slug, version, title: `AllAuth React SDK ${version}: ${title}`, summary, notes,
		announce: false, publishedAt: null, dateConfidence: "unknown", compatibility: "historical",
		upgradeUrl: "https://allauth.co/sdk/quickstart", changelogUrl: `https://allauth.co/releases/${slug}`,
		downloadUrl: `https://allauth.co/sdk/${filename}`, sha256,
		sourceUrl: `https://github.com/thegarty/allauth-sdk/tree/v${version}/packages/react`,
		provenance: [{ kind: previousVersion ? "archive-diff" : "archive", details: previousVersion ? `Reconstructed from the immutable ${previousVersion} and ${version} archives. The original publication date was not retained; archive file timestamps are not treated as release dates.` : `Reconstructed from the earliest retained allowlisted SDK archive, ${version}. The original publication date was not retained.`, files }],
	};
}

/** Historical notes describe verified archive contents, not unrecorded deployment dates or compatibility guarantees. */
export const sdkReleaseHistory: readonly HistoricalSdkRelease[] = [
	archive("1.4.2", "account dialog and profile update callbacks", "Refines the native account dialog and adds a host callback after a saved profile refresh.", [
		"Adds the optional async UserButton.onProfileUpdated callback for synchronizing an application's member profile after the native save and session refresh.",
		"Refines profile identity, verified-email and connected-account presentation, and retains profile editing after a successful save.",
		"Adds keyboard navigation between account sections and passes appearance options into the native account modal.",
	], ["README.md", "react.tsx", "header.tsx", "dialog.tsx", "header.css"], "1.4.1"),
	archive("1.4.1", "Apple, Microsoft and canonical OAuth callbacks", "Adds environment-advertised social providers and improves signed callback handling in the Next.js proxy.", [
		"SignIn and SignUp render Apple and Microsoft buttons when the selected environment advertises configured native providers.",
		"The Next.js proxy canonicalizes query parameters before signing mobile Google callbacks, preserving repeated values and opaque OAuth data.",
		"Allows Apple's checked HTTPS form_post callback while retaining other POST origin checks and native state verification.",
		"Adds a separate optional owned-photo lifecycle capability; the capability does not itself enable or configure a provider.",
	], ["README.md", "react.tsx", "branding.ts", "next.ts", "ui.tsx"], "1.4.0"),
	archive("1.4.0", "organisation teams, roles and connected support", "Adds native organisation teams and role controls, policy-driven password forms and explicit connected-application support integration.", [
		"Adds Teams and Roles views with server permission checks, custom-role selectors and scoped organisation operations.",
		"Introduces optional per-environment password policy and direct Google provider capabilities; native server policy remains authoritative.",
		"Adds opt-in connected-app support routes and a persistent actor/target banner, with browser-bound exchange and prior-session restoration.",
		"The archived README calls this a working candidate requiring a matching service deployment. The archive is retained here without inventing a deployment date or status.",
	], ["README.md", "organization-profile.tsx", "password-policy.ts", "support-server.ts", "support-banner.tsx", "client.ts", "next.ts"], "1.3.5"),
	archive("1.3.5", "signup policy and pending-email handoff", "Adds optional signup-policy capabilities and a local pending-email destination while preserving checked authentication return paths.", [
		"Uses optional signUpEnabled and emailVerificationRequired capabilities to adapt native signup to the selected environment.",
		"Adds SignUp.checkEmailUrl for a local pending-verification page while preserving the final verification callback and checked return intent.",
		"Extends checked return handling through native authentication and recovery links.",
		"The archived README labels this a working candidate. These notes describe its retained source rather than claim an unrecorded production rollout.",
	], ["README.md", "react.tsx", "auth-return.ts", "branding.ts", "dialog.tsx"], "1.3.4"),
	archive("1.3.4", "checked authentication return destinations", "Preserves local return destinations through native sign-in, signup and multi-factor continuation.", [
		"Exports safeAuthReturnTo, resolveAuthReturnTo, withAuthReturnTo and useAuthReturnTo helpers for bounded local destinations.",
		"SignIn and SignUp preserve validated returnTo values through links and callbacks, while explicit component destinations take precedence.",
		"Rejects external, API/proxy and encoded-alias destinations and validates callbackUrl on full-page native MFA continuations.",
	], ["README.md", "auth-return.ts", "react.tsx", "account-settings.tsx"], "1.3.3"),
	archive("1.3.3", "hidden account panels and tab focus", "Corrects account-panel visibility and tab overflow styling.", [
		"Forces hidden elements inside the SDK scope to remain hidden when host styles would otherwise affect their display.",
		"Constrains account-tab vertical overflow and moves keyboard focus outlines inside the tab viewport.",
	], ["header.css"], "1.3.2"),
	archive("1.3.2", "device-list style specificity", "Scopes device-list row styling more specifically to the AllAuth widget.", [
		"Changes the device-list row selector to include the AllAuth root, strengthening its padding, border and corner styles against host selectors.",
		"The archive comparison contains a focused stylesheet change; authentication and account logic are unchanged in this patch.",
	], ["header.css"], "1.3.1"),
	archive("1.3.1", "explicit organisation invitation handoff", "Preserves invitation intent in AccountSettings and verifies fresh membership before application callbacks.", [
		"Accepts an optional invitationId or a validated invitation query on the account page.",
		"Keeps invitation acceptance explicit for the verified invited address and checks membership, active organisation and session before selection callbacks.",
		"Supports retrying failed host setup without accepting an invitation twice, and opening an existing workspace from a closed invitation.",
	], ["README.md", "invitations.ts", "account-settings.tsx", "client.ts", "react.tsx"], "1.3.0"),
	archive("1.3.0", "account settings and profile photo drafts", "Adds a portable AccountSettings surface with profile, security and organisation tabs.", [
		"Adds AccountSettings and shared native profile panels, including optional profile-image upload drafts applied only on explicit profile save.",
		"Keeps modal headers and navigation fixed while their main content scrolls.",
		"Checks browser passkey support and presents native cancellation, recent-login and expired-challenge errors.",
		"Refines organisation member controls and protects the last owner from invalid changes in the interface.",
	], ["README.md", "account-settings.tsx", "avatar-upload.tsx", "passkey.ts", "dialog.tsx", "organization-profile.tsx"], "1.2.2"),
	archive("1.2.2", "menu positioning after asynchronous layout changes", "Repositions compact account and organisation menus when their anchors or contents resize.", [
		"Observes the menu, anchor and document viewport so asynchronously loaded session or organisation content can trigger a position update.",
		"Coalesces layout updates with requestAnimationFrame and disconnects observers and pending frames when the menu closes.",
	], ["header.tsx"], "1.2.1"),
	archive("1.2.1", "viewport-aware compact menus", "Corrects menu overflow measurements and positioning near viewport edges.", [
		"Measures against document viewport width and updates left/right placement rather than retaining a translated overflow box.",
		"Recomputes compact menu placement when the window resizes, maintaining a viewport margin.",
	], ["header.tsx"], "1.2.0"),
	archive("1.2.0", "native account and organisation management modals", "Adds opt-in avatar menus, a compact organisation switcher and shared native management dialogs.", [
		"Adds avatar UserButton and compact OrganizationSwitcher variants with opt-in modal management while retaining existing page/card defaults.",
		"Introduces controlled UserProfileModal and OrganizationProfileModal components and embedded profile/member views.",
		"Adds organisation selection and creation callbacks, awaiting application setup and retaining visible retry states on callback failure.",
	], ["README.md", "header.tsx", "dialog.tsx", "organization-profile.tsx", "react.tsx"], "1.1.1"),
	archive("1.1.1", "AllAuth attribution wordmark", "Adds the AllAuth wordmark to the native authentication footer attribution.", [
		"Packages a reusable wordmark component and updates the secured-by footer to use the branded mark with an accessible label.",
		"Updates the corresponding attribution styling and embedding guide without changing the authentication client or proxy.",
	], ["allauth-wordmark.tsx", "react.tsx", "styles.css", "BETTER_AUTH_UI.md"], "1.1.0"),
	archive("1.1.0", "managed application branding and email-first sign-in", "Adds centrally managed application branding and refines the portable authentication forms.", [
		"Loads and validates public application branding, including names, logos, support email, colours and attribution, through the same-origin SDK configuration endpoint.",
		"Adds branding overrides and shared authentication headers and footers to the portable sign-in, signup and password recovery forms.",
		"Refines email-first password sign-in presentation and packages a Google icon while retaining the existing client and server proxy.",
	], ["react.tsx", "branding.ts", "google-icon.ts", "styles.css", "BETTER_AUTH_UI.md"], "1.0.0"),
	archive("1.0.0", "portable React authentication and same-origin proxy", "The earliest retained public archive contains cookie-based React authentication, account and organisation components, and an app-bound server proxy.", [
		"Includes AllAuthProvider, SignIn, SignUp, password recovery, UserButton, UserProfile and OrganizationSwitcher backed by native cookie sessions.",
		"Provides inline multi-factor continuation and account security controls without exposing session credentials to browser code.",
		"Packages the optional Better Auth UI provider integration and a server-only same-origin Next.js proxy; the portable React components do not require Next.js.",
	], ["react.tsx", "client.ts", "next.ts", "ui.tsx", "BETTER_AUTH_UI.md"]),
];

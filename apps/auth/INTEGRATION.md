# Connecting applications to AllAuth

AllAuth hosts separate authentication projects on the existing Railway service
and PostgreSQL database. Cloudflare supplies DNS and the default transactional
email transport. Projects may explicitly select a scoped Resend sender as described
below. Each project has its own PostgreSQL namespace, auth secret, cookie names,
users, credentials, organizations, teams, sessions, metadata, audit records,
security policy and webhooks. The same email can be a different user in two
projects. Organizations represent customer tenants **within** a project; teams
belong to those organizations.

Verified platform accounts can create workspaces through `/admin/workspaces`.
Workspace owners and admins can create and manage their applications; members
receive summary access. The platform administrator retains global management.
Workspace teams govern the console and are separate from application end-user
organizations. An administrator in one project's user store has no authority over
the platform or another project. Project support impersonation creates a real,
short-lived session for that project's target user and preserves the actor.
Sensitive credential changes are blocked during impersonation.

This is a Clerk replacement foundation, not an automatic compatibility layer.
Existing applications, Clerk IDs and browser sessions still need migration.
Each application can have a Development and a Production environment. Each
environment is a separate authentication realm with its own tables, credentials,
origins, settings and logs. The same application groups them in the console;
switching environments does not copy users or organizations between them.
Application branding is shared across its Development and Production
environments; authentication and security settings remain environment-specific.

## Create a workspace and connect an app

Start at `/admin/workspaces` with a verified account. Create or select a
workspace, then open its Applications tab. Create a Development application,
connect the SDK, test a real sign-in, and add Production when ready. The
workspace/application/environment selectors retain the selected scope across
management and configuration pages. The application gallery groups the two
environments and explicitly identifies applications without Production.

Workspace Team and Settings support permission-checked membership, roles,
pending invitations and renaming. Only an owner or platform administrator can
change ownership or delete an empty workspace; the last owner is protected.
An invitation is stored for the recipient's verified email and appears when
they sign in to AllAuth. This workflow does not send an invitation email.
Default self-service limits are three owned workspaces, five applications per
workspace, two environments per application, 50 members and 20 pending
invitations; invitations expire after seven days. The server publishes effective
limits, and platform administrators are exempt from applicable quotas.

Give each environment a unique slug and its exact primary app origin, such as
`https://app.example.com`. Additional trusted origins must be exact; wildcard
hosts are refused. Local development permits explicit literal HTTP loopback
origins. Production requires HTTPS. The primary origin controls passkey RP
configuration and mailed app callbacks. Add a separate Development environment
for a localhost RP; its passkeys and sessions remain independent of Production.

Creation provisions all project tables transactionally and registers its
confidential AllAuth sign-in broker with an exact
`<app-origin>/api/allauth/callback/allauth` callback and S256 PKCE. Save the
one-time **proxy secret** in that app's server environment. The key authenticates
the app transport; user and organization permissions still come from the real
project session. Rotating this secret requires updating the app environment.
It is not an OAuth client secret and must never be put in `NEXT_PUBLIC_*`.

Project auth base path: `https://allauth.co/api/projects/<slug>/auth`.

Published default SDK: **1.4.3**, including automatic Google, Apple and Microsoft
sign-in, signup, organization and connected-support components. The versioned archive includes the native account dialog and profile-save refinements.
The prior 1.4.1 archive remains available with SHA-256
`4e473030ceebebd3273cb200d374587f9478ccc8bafd1bf0c07845a54b10701d`.
Older published archives remain immutable.

Open the selected environment's `/admin/setup-guide` for populated server
variables, integration snippets and the SDK download. This release ships a
direct tarball at
[/sdk/allauth-react-1.4.3.tgz](https://allauth.co/sdk/allauth-react-1.4.3.tgz).
This is a direct download; the package is not published to npm. Older SDK
archives remain available so existing integrations can upgrade deliberately.

For a Next.js application, install the direct tarball and its pinned peers:

```sh
pnpm add https://allauth.co/sdk/allauth-react-1.4.3.tgz better-auth@1.7.7 @better-auth/passkey@1.7.7 lucide-react@^0.575.0
```

Alternatively, run `pnpm --dir apps/auth/sdk pack` from the AllAuth repository
and install the generated local tarball. The source package is `apps/auth/sdk`.
Use `transpilePackages: ["@allauth/react"]`
in the consuming Next.js configuration because this private package exports
TypeScript source. Import `@allauth/react/styles.css` from the app layout;
appearance uses CSS variables and component `className`/`style` props.

Create `app/api/allauth/[...all]/route.ts` in the consuming app:

```ts
import { createAllAuthProxy } from "@allauth/react/next";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
const proxy = createAllAuthProxy({
  project: process.env.ALLAUTH_PROJECT!,
  proxySecret: process.env.ALLAUTH_PROXY_SECRET!,
  appOrigin: process.env.APP_ORIGIN!,
  allauthURL: "https://allauth.co",
  // Optional: return the client IP verified by this app's hosting ingress.
  // Never trust an arbitrary browser-supplied forwarded-IP header.
  // getClientIP: (request) => verifiedIngressClientIP(request),
});
export const GET = proxy;
export const POST = proxy;
```

The proxy permits selected native self-service endpoints, checks same-origin
browser writes, bounds request size, signs the method/path/body/origin and
approved client IP, and rewrites only this project's HttpOnly cookies to the app
domain. It strips persistent credential fields from browser JSON and does not
forward browser bearer credentials or platform/other-project cookies. It blocks
administration, control, token-exchange and schema endpoints. For non-Next.js
apps, implement this same server-side transport contract rather than exposing
the proxy key or relying on third-party cookies.

Create a client provider in the consuming app:

```tsx
"use client";
import { AllAuthProvider } from "@allauth/react";

export function AuthProvider({ children }: { children: React.ReactNode }) {
  return (
    <AllAuthProvider afterSignInUrl="/" profileUrl="/account">
      {children}
    </AllAuthProvider>
  );
}
```

SDK **1.3.4** loads the selected application's public branding and enabled sign-in
options automatically through `/api/allauth/sdk/config`. The server proxy binds
that request to the configured project. The default provider does not need a
hardcoded name, logo or capability list. Leave `capabilities` unset to use this
configuration fetch; explicitly supplied capabilities skip it. Existing
`branding` overrides remain available for applications that deliberately supply
their own name or logo.

With an application selected, open **Configure → Application → Settings**
(`/admin/settings?project=<slug>`). Workspace owners/admins and platform
administrators can manage the application name, optional support email, light
and dark logos, favicon, light/dark accent colors, and AllAuth attribution.
These presentation settings belong to the application and apply to both its
Development and Production environments. Authentication policies, identities
and sessions remain isolated by environment.

Logos accept PNG, JPG or WebP; favicons accept PNG or ICO. Each file is limited to
2 MB. Images use Cloudflare storage when it is configured; the console disables
uploads and shows the unavailable state otherwise. Uploads save the selected
asset immediately. Other field edits and asset removals take effect after
**Save changes**. Version checks reject conflicting edits rather than overwriting
another administrator's changes.

The portable sign-in/sign-up cards use the saved name and theme-specific logo
and accent, with the optional support contact and attribution in their footer.
A new configuration load picks up saved settings; `useAllAuth().reloadConfig()`
refreshes an already-mounted provider. Light/dark presentation follows the
host's theme. `useAllAuth().publicBranding` exposes the safe public fields,
including `faviconUrl`. The SDK does **not** modify the embedding application's
document head or install its favicon automatically. The host application decides
whether and how to use that URL in its own metadata.

`SignIn` and `SignUp` share a centered branded card, social sign-in, a separate
footer and accessible password visibility controls. Sign-in asks for email
before showing the password; this first step validates locally and does not
check whether an account exists. Sign-up combines first and last name into
the native Better Auth `name` field. The components preserve native Google,
verification, recovery and two-factor flows.

Theme the same component using `--allauth-background`, `--allauth-surface`,
`--allauth-footer-background`, `--allauth-foreground`, `--allauth-muted`,
`--allauth-border`, `--allauth-accent`, `--allauth-accent-foreground`,
`--allauth-accent-hover`, `--allauth-focus`, `--allauth-placeholder` and
`--allauth-shadow`. Set those variables on a scoped `.allauth` selector in the
app's light/dark theme. No host application layout is required inside the card.

Embed `SignIn`, `SignUp`, `ForgotPassword`, `ResetPassword`, `UserButton`,
`UserProfile` and `OrganizationSwitcher` inside that provider. `useAllAuth()`
exposes the native cookie client. Use `/sign-in`, `/sign-up`, `/forgot-password`,
`/reset-password` and `/account` pages to match the default callbacks. Pass a
local `forgotPasswordUrl` to `SignIn`. The account component includes profile,
password, TOTP enrollment/recovery, passkey management and safe session controls.
Organization actions use actual membership and owner/admin permission checks.

## Standard social sign-in

Include Google, Apple and Microsoft in every new application's setup review.
Use the shared `SignIn` and `SignUp` components without hardcoded capability
flags or a manually maintained provider list. They load the exact environment's
enabled providers and handle return paths and native MFA automatically. The
optional `AllAuthUIProvider` also discovers providers when its `socialProviders`
prop is omitted; an explicit array remains an override.

Configure direct Google under User & authentication → Social connections. Apple
requires an Apple Services ID, signing key and HTTPS return URL. Microsoft requires
an Entra Web app registration, client ID, client-secret value and registered return
URL. Their server-only maps are keyed by exact environment slug:
`ALLAUTH_PROJECT_APPLE_PROVIDERS` and `ALLAUTH_PROJECT_MICROSOFT_PROVIDERS`.
Missing credentials leave that provider unavailable. Development and Production
use independent configuration; provider credentials never enter app browser code.

The environment's setup guide displays the exact app return URLs. See
[Apple setup](../../docs/content/docs/integrations/allauth-tenant-apple.mdx) and
[Microsoft setup](../../docs/content/docs/integrations/allauth-tenant-microsoft.mdx)
for registration, private-relay email and tenant-audience requirements. Upgrade
existing apps to SDK 1.4.2, then verify each configured provider with a real account.

## Native header menus and account dialogs (SDK 1.3.4)

The portable SDK provides native account and organisation menus for app headers.
Their default page/card behaviour remains compatible with SDK 1.1.1. Opt in to
compact menus and modals with these props:

```tsx
<UserButton
  variant="avatar"
  managementMode="modal"
  onProfileUpdated={async () => refreshApplicationMember()}
/>
<OrganizationSwitcher
  variant="compact"
  managementMode="modal"
  onSelect={async (organization) => enterAppTenant(organization.id)}
  onCreate={async (organization) => bootstrapAppTenant(organization.id)}
  onOrganizationChange={async (organization, reason) => {
    if (reason === "update") await refreshTenant(organization.id);
    if (reason === "leave" || reason === "delete") navigateToTenantChooser();
  }}
/>
```

Selection and creation set the real native active organisation before invoking
host callbacks. `onOrganizationChange` receives `select`, `create`, `update`,
`leave` or `delete`; hosts should avoid repeating selection/navigation work
already handled by `onSelect` or `onCreate`. If app bootstrap fails after native
creation, **Retry setup** reuses the created organisation rather than creating
another one. The host remains responsible for its application tenant records
and authorisation. Menu rows never invent memberships or platform-admin tenant
access.

SDK 1.4.2 keeps account management in the native responsive dialog. The optional
`UserButton.onProfileUpdated` callback runs after native profile save and session
refresh, so a connected application can refresh its own member data without
replacing the standard profile or security controls. Existing page mode remains
available.

`UserProfileModal` accepts `open`, `onClose`, optional
`initialSection="profile" | "security"` and `onUpdated`. `UserProfile` accepts
`section="all" | "profile" | "security"` and `embedded`; its defaults retain the
complete page. Profile changes update the native name/avatar and refresh the
session without leaving the current app screen. Connected accounts show their
actual provider IDs; an `allauth` broker identity is labelled **AllAuth**.
Unsupported phone and multiple-email controls are not displayed.

`OrganizationProfile` accepts `organizationId`, `view="general" | "members"`,
`embedded`, `onUpdated`, `onDeleted` and `onLeft`. Its matching
`OrganizationProfileModal` additionally accepts `open`, `onClose` and
`initialSection`. Both use fresh native membership, invitations and role checks;
last-owner actions are protected and deletion requires an owner to type the
organisation name. Backend native permissions remain authoritative.

Dialogs include Escape dismissal, trapped/restored focus and body scroll locking.
Menus support keyboard navigation and close outside the menu. All components
use the existing same-origin proxy. Import `@allauth/react/styles.css` once and
set the normal `--allauth-*` tokens, or `--allauth-modal-accent`, to match the host.
The new components require React DOM matching the supported React version.

The hosted pages use the official Better Auth UI shadcn components, version
1.7.27. Sign-in, account/security and organization surfaces share the management
console's AllAuth styling and responsive navigation; native authentication and
session actions remain functional. For an application that wants those same
registry components, see [the optional UI provider recipe](./sdk/BETTER_AUTH_UI.md).
It uses the same server proxy and isolates its UI query cache by project.
The administration console supports organization creation and profile management,
members, invitations, teams and custom permission roles within the selected
environment. Creation requires an existing verified owner in that environment.
The final owner cannot be removed or downgraded, directory-managed membership
is protected, and deleting an organization requires its exact ID and removal
of enterprise connections/application bindings first. Members also manage their
organizations through the account components using native permissions.

Google sign-in uses the central AllAuth broker, then creates a distinct user and
session in the chosen project. That federation can reuse the platform Google
login; project memberships, passwords and session state are still independent.
When a platform session is absent, the broker carries a signed `idp_hint=google`
and its `/oauth/login` entry starts native Google authentication immediately.
After Google (and any required MFA or consent), native authorization returns to
the application's exact registered callback; the website's project cookie stays
on its own origin. Generic OAuth clients without a provider hint keep the normal
AllAuth login choices. Only a verified, unexpired native authorization request
for an enabled client can start the automatic Google handoff. Google credentials
remain server-side in AllAuth. Applications using the existing SDK and server
proxy receive this flow fix without changing their OAuth credentials or package.
An existing verified email in a project is not automatically linked to a new
broker identity. Link identities deliberately from an authenticated account.

Applications must enforce authorization on their own **server**. Validate the
project session through the same signed server proxy, and verify the current
organization membership for the resources being accessed. A React sign-in gate,
browser-selected organization or public metadata field does not protect app
data. Store app records against this project's user/organization IDs.

The console has environment-scoped analytics, users, organizations, sessions,
audit, authentication configuration, security and webhook pages. Analytics
supports date ranges, daily/weekly/monthly buckets and cohort drilldowns. It
measures authenticated activity; it does not infer product engagement or import
Clerk history. Missing collection periods are marked unknown rather than zero.
See [metric definitions](./docs/analytics.md) and
[authentication policy](./AUTHENTICATION_POLICY.md) for effective settings,
version conflicts and required-MFA prerequisites.

Configure webhook destinations deliberately; signed
deliveries are durable with retries and real history, and event snapshots omit
credentials/private metadata. No destination is created automatically. Consult
[PLUGINS.md](./PLUGINS.md) and the console Plugins page for the installed free
libraries, active flows and provider requirements. SSO/SCIM require actual
organization/provider setup; SMS, CAPTCHA and payment services remain inactive.

## Account and frontend API domains

Open `/admin/domains` with an application environment selected. Its default
account and frontend API addresses are shown separately. A custom domain
reservation creates `accounts.<customer-domain>` for hosted account pages and
`frontend-api.<customer-domain>` for authentication API routing. Hostnames belong
to that exact environment; they do not share its user store with other apps.

Add the exact ownership TXT, routing CNAME and any certificate-validation
records shown by the console. Copy the record names and values, then use
**Verify DNS and TLS**. Ownership, routing and TLS have independent status and
last-check evidence. Verification is manual; no continuous DNS monitoring is
implied. Both names must pass the backend's checks before the pair routes.
Removal disables routing first and retains the reservation if provider cleanup
is uncertain; retry cleanup before reusing the hostname.

The signed Cloudflare gateway, SaaS fallback and readiness-enabled Railway
deployment were verified on 7 October 2026. Unknown hosted names return 404;
forged direct gateway requests return 403. A reservation does not establish a
customer's DNS or certificate: add the supplied TXT/CNAME records and verify
both hostnames' TLS before using that domain. No customer hostname was created
as a rollout fixture. See [hosted domain operations](./docs/hosted-domains.md).
The supported SDK proxy recipe above continues to use the canonical AllAuth
service origin.

## Project-only Resend email

AllAuth owns verification, password-reset and native organisation-invitation
emails. Configure their provider on the AllAuth server, not in the embedding
application's browser or SDK proxy. The existing Cloudflare sender continues
for the platform and every project without an explicit override.

For project `exampleapp-production`, set these server-only environment variables:

```dotenv
ALLAUTH_PROJECT_EXAMPLEAPP_PRODUCTION_EMAIL_PROVIDER=resend
ALLAUTH_PROJECT_EXAMPLEAPP_PRODUCTION_EMAIL_FROM=security@exampleapp.example
ALLAUTH_PROJECT_EXAMPLEAPP_PRODUCTION_EMAIL_FROM_NAME=ExampleApp
ALLAUTH_PROJECT_EXAMPLEAPP_PRODUCTION_RESEND_API_KEY=<private sending-only key>
```

The prefix is the exact project slug with hyphens changed to underscores and
uppercased. Configure `EXAMPLEAPP_DEVELOPMENT` independently for the separate
development realm. Verify the sender domain in Resend and publish the exact
DKIM/SPF records returned for that domain before enabling production delivery.
Use a sending-only key restricted to that domain. No key belongs in a public
environment variable or application metadata.

Explicit Resend selection fails closed if its key or sender is missing; it
does not fall back to the shared sender. HTTP failures and provider error
bodies stay private. A successful send requires a Resend acceptance ID and
does not prove inbox delivery. Transport selection applies to the existing
branded auth templates and retains each application's callback URLs.

After changing these server variables, restart/redeploy the AllAuth service.
The embedding application does not need a new SDK or deployment for this change.

The design rationale and remaining product work are recorded in the
Clerk reference review (private operational evidence).

## Standard platform OIDC applications

The platform also retains its conventional central-identity OIDC integration.
This uses the **platform** user store, not an isolated project's SDK tenant.
Choose Projects above for Clerk-style separate application user stores.

As a platform administrator, open `/admin/applications` and register a separate
client for each application/environment.

- Use a confidential client for a server application. Save its one-time secret
  in that app's server secret store.
- Use a public client for a browser-only application. It receives no secret.
- Register exact HTTPS callback URLs. Enable localhost development callbacks
  explicitly for a development client, and list the exact loopback URLs.
- PKCE is required for both kinds of client. Dynamic public registration is off.
- For organization access, list approved AllAuth organization IDs and a specific
  HTTPS API resource URI. Identity-only clients do not receive org claims.

Production issuer: `https://allauth.co`.
Discovery: `https://allauth.co/.well-known/openid-configuration`.
Authorization server metadata:
`https://allauth.co/.well-known/oauth-authorization-server`.

Read endpoints and supported methods from discovery. The provider uses the
standard `openid profile email` scopes. Request `offline_access` only when the
app needs refresh tokens and `organization:read` only for an approved org/resource
binding. Send the exact `resource` in both authorization and token requests.

## Better Auth applications

An app that uses Better Auth for its local sessions can use its official Generic
OAuth plugin. Register that app's exact callback:
`https://your-app.example/api/auth/callback/allauth`.

```ts
import { betterAuth } from "better-auth";
import { genericOAuth } from "better-auth/plugins";

export const auth = betterAuth({
  // Keep this application's own database, baseURL, secret and route handler.
  database: appDatabase,
  plugins: [
    genericOAuth({
      config: [
        {
          providerId: "allauth",
          clientId: process.env.ALLAUTH_CLIENT_ID!,
          clientSecret: process.env.ALLAUTH_CLIENT_SECRET!,
          discoveryUrl: "https://allauth.co/.well-known/openid-configuration",
          requireIdTokenVerification: true,
          tokenEndpointAuth: { method: "client_secret_basic" },
          scopes: ["openid", "profile", "email"],
          pkce: true,
        },
      ],
    }),
  ],
});
```

The snippet illustrates basic identity configuration, not a complete app server.
It does not propagate impersonation actor claims into the app's local session;
that requires per-session integration with the verified ID token. Use the app's
existing adapter and Next.js/framework handler. On the client:

```ts
await authClient.signIn.social({ provider: "allauth", callbackURL: "/dashboard" });
```

For an organization API, add `organization:read`, set
`authorizationUrlParams: { resource: "https://api.your-app.example" }`,
`tokenUrlParams` and `refreshTokenParams` with the same resource. The resource
must exactly match the registration. The app must validate the resulting access
token and derive tenant access from verified claims, not from a browser field.

Other OIDC libraries can use the same discovery document and client registration.
Use a library that validates state, nonce, PKCE, signature, issuer, audience,
algorithm and expiry. Store confidential client secrets and refresh tokens on
the server. Access/ID tokens expire after five minutes; refresh tokens rotate.
Native metadata currently uses `acr="0"`; do not infer a standard MFA assurance
level from it or assume an `amr` claim is present.

## Identity, organizations and impersonation

The SDK 1.4.0 candidate supports opt-in connected-application support sessions.
Enable `supportAccess: { enabled: true }` on `createAllAuthProxy`, enable
`supportAccess` on the shared `AllAuthProvider` (or `AllAuthUIProvider`), then
register the exact application proxy `/support/callback` URL in the selected
environment's User & authentication → Support access settings. Custom proxy
mounts must set the same `basePath` on both server and provider. All three steps
are required; existing integrations remain disabled.

Local handoff tests need distinct service/app hostnames, such as service
`localhost:3002` and app `127.0.0.1:3004`, with that exact app origin registered.
Cookies ignore ports; two `localhost` ports share the native cookie and cannot
represent independent console/app sign-ins.

After starting impersonation in Users, **Open connected app** transfers the same
bounded support session through browser-bound state, PKCE and one-use codes over
the signed server proxy. No bearer is placed in a URL. The persistent app banner
identifies the acting administrator and target and ends support. Ending from
either domain revokes the native session. The SDK restores a still-valid prior
app session without extending its original expiry or browser persistence; it
preserves a newer login and never restores an expired/revoked session. Restoration
is bounded to 20 minutes and the current integration key. App-owned sensitive
actions must still enforce their own authorization rules.

Use `(issuer, subject)` as the stable identity key. Do not match existing users
solely by an unverified email address or assume AllAuth IDs equal Clerk IDs.
User profile claims are available through UserInfo; profile/email claims should
not be assumed to exist in every ID token.

Organization-scoped access tokens carry:

- `https://allauth.co/organization_id`
- `https://allauth.co/organization_role`

Claims require an allowed org, its resource and current membership. Check the
API audience as well as the issuer. Enforce application permissions separately
from identity authentication. Existing signed access tokens can remain valid for
their five-minute lifetime after revocation. Introspection can detect an ended
login session, but retains the token's issued organization claims. Immediate
membership/role enforcement requires a fresh membership check.

Impersonated JWT access tokens and ID tokens preserve `act.sub` and
`https://allauth.co/impersonated_by`. Apps should display the acting-admin state
and restrict sensitive actions. Offline refresh access is denied during
impersonation. A plain subject-only local session would discard this context;
preserve the actor information when constructing the app session. Identity-only
access tokens without a resource are opaque; their current introspection response
does not include these actor extensions. Use the verified ID token to retain the
actor for local sessions, and resource-bound JWT tokens for APIs needing it.

Normal sign-out clears the browser session and preserves consented offline
grants. It does not automatically terminate every connected application's local
session. Apps need their own logout/session-revocation integration; password
recovery, bans and explicit revocation invalidate the stored grants covered by
the service policy.

## Hosting and operations

Run the standalone Node image with your own PostgreSQL connection and provider configuration. See the [self-hosting guide](../../docs/SELF_HOSTING.md) for deployment, migrations, backups and recovery. Application integrations use their scoped client/proxy credentials, never database or operator credentials.

## Clerk migration sequence

The scoped [hosted Clerk importer](../../docs/content/docs/integrations/allauth-clerk-import.mdx)
and `allauth_users_import_clerk` MCP operation provide dry-run batches, repeat-safe
source mappings and bcrypt compatibility while retaining existing scrypt
credentials. This is an explicit administrator migration operation; it does not
transfer Clerk sessions or MFA/passkeys and does not change any connected app automatically.

1. Select an initial application and register its production/development clients.
2. Export its users, verified identities, organizations, memberships, roles and
   required metadata; define explicit Clerk-to-AllAuth ID mappings.
3. Import into staging and verify email/account-linking rules. Imported users
   without a compatible password credential need a recovery or Google/SSO flow.
4. Replace Clerk SDK calls, middleware, organization authorization and metadata
   access in that app. Keep the app's own data tenant boundaries intact.
5. Replace event/webhook consumers once their destinations and delivery contract
   are specified. The service provides a signed durable webhook outbox with
   retries and delivery history; configure each application's destination in
   its project. No destination is created automatically.
6. Verify sign-in, recovery, org switching, invitations, bans, session revocation,
   SSO and impersonation in staging. Plan forced reauthentication for old Clerk
   sessions and then cut over the first app.

Clerk components and sessions are not compatible with Better Auth automatically.
This repository supplies the identity service; each application's migration is
a separate implementation step. SMS, billing and unrelated demo integrations
are not enabled by installing authentication plugins.

No existing application's Clerk SDK, users, organizations or sessions have been
migrated by the hosting setup.

Official references: [Generic OAuth](https://www.better-auth.com/docs/plugins/generic-oauth),
[OAuth provider](https://www.better-auth.com/docs/plugins/oauth-provider),
[Clerk migration](https://www.better-auth.com/docs/guides/clerk-migration-guide).


### Account-page invitation intent (SDK 1.3.4)

Mount `AccountSettings` on the native invitation email's account destination.
The component reads validated `?invitation=` or an explicit `invitationId` prop
and opens Organisations for review. SDK 1.3.4 preserves a checked relative
`returnTo` through its native sign-in, sign-up, recovery and MFA flows. Custom
authentication pages must carry the checked destination themselves. Explicit
component callback props take precedence over query intent. Joining requires the invited verified account to choose
Accept; loading the link or signing up does not accept automatically. The SDK
checks fresh native membership and session, activates the actual organisation,
then calls `onSelect` and `onOrganizationChange(organization, "select")` so the host
can resolve its own workspace. Retry setup resumes an already accepted invite
without repeating acceptance or successful host callbacks. An existing member
can Open workspace even if the invitation was cancelled or already accepted.

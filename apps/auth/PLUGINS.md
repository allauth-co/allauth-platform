# Free plugin inventory

This application uses the official Better Auth 1.7.7 source. Free plugin code does not make Railway, email, SMS, payment processing or other external services free. The administrator **Plugins** page reports installed code and actual activation separately, for the platform or the selected project. Installing an integration does not create an external account, register a webhook or authorize charges.

AllAuth's managed workspace subscriptions use a separate server-only Stripe client (`@allauth/stripe-client`, an alias for Stripe 23.1.0), Checkout, Customer Portal and a durable webhook/reconciliation worker. This is platform billing, not the tenant-level `@better-auth/stripe` plugin below. Hosted checkout and commercial enforcement are explicit rollout flags; self-hosted mode requires neither Stripe nor a subscription. See [commercial plans](../../docs/content/docs/integrations/allauth-commercial-plans.mdx).

The inventory follows the [official plugin index](https://www.better-auth.com/docs/plugins) and the individual documentation files in this repository. Provider-maintained integrations listed there are identified separately below. Versions and licenses were checked against published npm metadata and package/repository license files during this implementation; they are pinned in `package.json` and the lockfile. New plugin code must pass migrations, native flow checks and release verification before it is described as deployed.

The hosted authentication and account pages use the MIT-licensed [Better Auth UI](https://better-auth-ui.com) shadcn registry with `@better-auth-ui/core` and `@better-auth-ui/react` **1.7.27**. This is a frontend component layer. Source and retained licenses are documented in [ATTRIBUTION.md](./components/better-auth-ui/ATTRIBUTION.md). For embedding applications using the optional v1 registry provider, see the [SDK v2 UI upgrade guide](./sdk/UI_UPGRADE.md). Session controls use opaque IDs, and unconfigured uploads remain hidden.

## Authentication and administration

| Plugin | Code | Configuration and limits |
| --- | --- | --- |
| Admin | `better-auth/plugins` | Existing verified platform administrator gate; project management does not inherit a project user's role as platform authority. |
| Organizations, teams and access control | `better-auth/plugins` | Existing organization membership and role checks; users and teams stay within their project. |
| Two-factor authentication | `better-auth/plugins` | TOTP and backup codes; all new native session methods pass the production MFA hook. Email OTP as a second factor is deliberately disabled. |
| Passkeys | `@better-auth/passkey` 1.7.7, MIT | Requires a compatible browser and exact configured application origin/RP ID. |
| Magic links and email OTP | `better-auth/plugins` | Use the selected environment's Cloudflare sender or explicitly configured project Resend transport. Inventory readiness uses the same credential checks as delivery; actual delivery still requires working provider configuration and sender DNS. |
| Username | `better-auth/plugins` | Enabled for platform and projects. Email remains required by the native user model. |
| Anonymous | `better-auth/plugins` | Enabled only in projects. Account creation forces `role: guest`, `emailVerified: false`; native guest linking/upgrading remains in the same realm. It cannot bypass verified administration/organization gates. |
| Google One Tap | `better-auth/plugins` | Platform only, when the platform Google ID/secret pair exists. The JavaScript origin must be registered with Google. Projects use their configured AllAuth broker. MFA still applies to new sessions. |
| SIWE | `better-auth/plugins` + `viem` 2.57.3, MIT | Uses local EOA signature recovery with native nonce/replay/domain/time checks and an additional signed-URI origin check. No RPC account, ENS resolution or smart-contract wallet verification is configured. Wallet-only created accounts remain unverified. |
| Multi-session and last login method | `better-auth/plugins` | Existing native methods and project-isolated cookie names. |
| Generic OAuth | `better-auth/plugins` | Each project has its AllAuth broker. Platform custom-provider code is installed with an empty provider list, requiring credentials and exact callbacks before activation. |
| SSO | `@better-auth/sso` 1.7.7, MIT | Registration/domain verification management is installed. Actual enterprise login requires an organization's verified domain and its own OIDC/SAML provider configuration. |
| SCIM | `@better-auth/scim` 1.7.7, MIT | Management/catalog code is installed; active provisioning requires the hash secret, verified organization SSO binding and external provisioning client. Tokens are one-time displayed, hashed and independently revoked/rotated. |
| API key | `@better-auth/api-key` 1.7.7, MIT | Existing scoped credentials. Keys do not authenticate a browser or create an administrator session. |
| JWT | `better-auth/plugins` | Existing configured issuer/JWKS and approved OAuth resources. |
| Bearer | `better-auth/plugins` | Signed session tokens for server integrations only. Native bearer token response headers are suppressed for requests with browser Origin/fetch metadata, as well as management, audit, schema, device consent and agent protocol paths. BFF/browser code never forwards bearer credentials. |
| One-time token | `better-auth/plugins` | Hashed native token identifier, one-minute expiry, server-only generation, no automatic token headers and no session cookie on verification. Browser and app BFF access are excluded. |
| Agent Auth | `@better-auth/agent-auth` 0.6.2, MIT | Delegated only, dynamic host registration disabled, inline Ed25519 public keys, no capabilities/default host capabilities, and no executable actions. Fresh verified cookie ownership guards user-managed changes; native signed-host/agent operations retain their signature and owner checks. Remote JWKS URLs are rejected. Replay checks are currently per-process; a shared replay store is required before granting real actions across multiple replicas. Agent capability approval pages/actions are not active with the empty capability catalog. |
| Custom session/access helpers | Included native code | Existing safe session shaping and access checks; these utilities are not additional token grant endpoints. |

## OAuth, schema and security

| Plugin | State | Reason or requirements |
| --- | --- | --- |
| OAuth Provider | Enabled, `@better-auth/oauth-provider` 1.7.7, MIT | Managed registration, OAuth 2.1 authorization code with S256 PKCE, refresh rotation, OIDC discovery and scoped resources. |
| Device Authorization | Installed/native flow enabled with client restriction | Uses **`oauthDeviceAuthorization()`**, paired with the existing OAuth provider. Code issuance is `/device/code`; redemption is `/oauth2/token`. Only explicitly approved clients may request `urn:ietf:params:oauth:grant-type:device_code`. Global support alone does not activate an existing application's grant. |
| Device approval screen | `/device`, optional `?project=slug` | Review is an explicit action because native `GET /device` claims a pending code for the signed-in reviewer. Approve/deny require a verified, non-impersonated login made within five minutes. Project review requires an existing project session; this screen does not invent a hosted project login flow. Never expose device codes in logs or approve on page load. |
| Have I Been Pwned | Enabled | Native free Pwned Passwords range query sends only the first five SHA-1 hash characters and requests padding. Password creation/changes, including remapped project admin routes, fail closed when lookup fails. Ordinary sign-in does not perform an external range request. This free external API must be reachable. |
| i18n | Enabled, `@better-auth/i18n` 1.7.7, MIT | Native built-in translations, English fallback, Accept-Language detection. This translates server errors, not all application copy. |
| OpenAPI | Privileged JSON only | `/open-api/generate-schema` requires an authoritative verified non-impersonated administrator cookie and returns `no-store`. The public Scalar `/reference` page is disabled. |
| CAPTCHA | Installed, needs provider setup | Native `captcha()` supports Cloudflare Turnstile, reCAPTCHA, hCaptcha, CaptchaFox and Vercel BotID. Turnstile can use a free service, but still requires real site/secret keys and client challenges sent as `x-captcha-response`. Enabling the server hook without challenge-capable sign-in/SDK UI would block legitimate sign-in. No paid challenge service has been activated. BotID additionally requires its supported Vercel deployment. |
| Phone number/SMS | Installed, needs provider setup | Native `phoneNumber()` requires an actual `sendOTP`/recovery sender implementation, provider account/credentials, phone ownership/recovery UI and abuse limits. No SMS provider is configured; actual message delivery may be billed. |
| OAuth proxy | Installed, optional/inactive | A preview-host integration, not needed on the canonical production origin. It requires explicit preview hosts/trusted origin configuration. |
| OAuth popup | Installed, incompatible/inactive | Native popup handoff gives the opener a session token, contrary to this application's cookie-only BFF boundary. |
| CIMD | Installed, `@better-auth/cimd` 1.7.7, MIT; inactive | Unauthenticated dynamic client metadata discovery conflicts with managed-only application registration. Future activation also requires the native DNS-pinned special-address-rejecting fetch transport. |
| MCP | Installed, `@better-auth/mcp` 1.7.7, MIT; inactive wrapper | Current native `mcp()` wraps the OAuth Provider and must not run alongside a separate `oauthProvider()`. MCP resource-server integration would use the authoritative OAuth server and an explicit resource/protocol configuration; no duplicate token endpoint is added. |
| Legacy OIDC provider | Superseded | Current OAuth Provider already supplies OIDC. Do not add a duplicate legacy grant/token implementation. |
| Test utilities | Development only | Included native test helper code; never registered in production. |
| Expo/Electron and database/framework adapters | Available repository integrations, outside this web runtime | Native/desktop client integrations and alternate database adapters are not independent authentication features to register on the Node web server. They require their matching target application/framework. |

## Provider-maintained free libraries staged inactive

All the following integration code is free to use under its stated license. None is registered in the authentication plugin array without its own provider account and application-specific setup. No production billing, tracking or webhook delivery is activated simply by installing these packages. Fees, transaction charges, provider usage limits and license obligations are separate from Better Auth's MIT license.

| Official documentation | Pinned plugin and SDK | License evidence | Activation requirements |
| --- | --- | --- | --- |
| [Stripe](https://www.better-auth.com/docs/plugins/stripe) | `@better-auth/stripe` 1.7.7; `stripe` 22.6.2 | MIT, [native plugin](https://github.com/better-auth/better-auth/blob/main/LICENSE.md) / [Stripe SDK](https://github.com/stripe/stripe-node/blob/master/LICENSE) | Own Stripe secret key, webhook signing secret, approved product/price mappings, authenticated customer ownership and checkout/portal UI. SDK 23 is outside this native plugin's declared peer range. |
| [Polar](https://www.better-auth.com/docs/plugins/polar) | `@polar-sh/better-auth` 2.1.0; `@polar-sh/sdk` 1.0.2 | Adapter repository [Apache-2.0](https://github.com/polarsource/polar/blob/main/LICENSE); SDK published metadata MIT | Own Polar access token/environment, product IDs, configured success/return URLs and webhook secret for webhook integration. |
| [Autumn](https://www.better-auth.com/docs/plugins/autumn) | `autumn-js` 1.3.62 (`autumn-js/better-auth`) | MIT in published npm metadata | Own `AUTUMN_SECRET_KEY`, configured plans/features, customer scoping, usage/billing UI. Downstream payment and hosted-service charges remain separate. |
| [Creem](https://www.better-auth.com/docs/plugins/creem) | `@creem_io/better-auth` 2.0.4; bundled Creem SDK | MIT in published npm metadata | Own `CREEM_API_KEY`, `CREEM_WEBHOOK_SECRET`, distinct test/live environment, product/access mappings and success/portal UI. |
| [Commet](https://www.better-auth.com/docs/plugins/commet) | `@commet/better-auth` 8.1.0; `@commet/node` 9.4.0 | MIT in both published npm manifests | Own `COMMET_API_KEY`, customer/products/features/seat policy, optional `COMMET_WEBHOOK_SECRET`, authenticated portal/subscription UI. |
| [Chargebee](https://www.better-auth.com/docs/plugins/chargebee) | `@chargebee/better-auth` 1.2.0; `chargebee` 3.34.0 | Plugin published metadata MIT; SDK published LICENSE MIT | Own `CHARGEBEE_API_KEY`, `CHARGEBEE_SITE`, item-price IDs, subscription/portal UI, webhook Basic Auth username/password and signature/event policy as applicable. This integration is an additional official documentation page even though it was absent from the index list. |
| [Dub](https://www.better-auth.com/docs/plugins/dub) | `@dub/better-auth` 0.0.6; `dub` 0.73.5 | Plugin published README says MIT; SDK published LICENSE MIT | Own Dub API token, actual conversion/lead configuration and optional own OAuth client ID/secret. No lead/customer data is sent while inactive. Do not infer the SDK/plugin license from Dub's separate open-core hosted product license. |

Some packages omit a `license` field even though their repository or published package contains license evidence; the table records the source actually inspected. Registry versions can change. Preserve the pinned version and review its source/license and security behavior before enabling or upgrading it.

## Release checks

Focused tests cover factory composition, cookie/server token boundaries, guest role writes, freshness, wallet origin binding, remote agent key rejection, honest status reporting and local device review navigation. Native endpoint/security tests and the root's database/browser checks remain the authority for actual flows. The Plugins page reports capabilities and configuration, not proof that an external enterprise/payment provider has been connected. Existing Clerk applications and users remain a separate migration task.

# AllAuth platform service

AllAuth provides managed and self-hosted authentication, account security and organization management. The service lives in `apps/auth` and supports separate development and production environments.

The platform source is available under the MIT license. The React SDK is published separately as versioned GitHub releases and downloadable archives. [MIT license](../../LICENSE.md) · [Third-party notices](../../THIRD_PARTY_NOTICES.md) · [SDK releases](https://github.com/allauth-co/allauth-sdk/releases)

- [Self-hosting and recovery](../../docs/SELF_HOSTING.md)
- [Hosted plans](https://allauth.co/pricing)
- [React SDK v2 quickstart](https://allauth.co/sdk/quickstart) and [upgrade guide](https://allauth.co/sdk/quickstart#upgrade)
- [Release requirements](RELEASING.md)
- [Contributing](../../CONTRIBUTING.md) and [security reporting](../../SECURITY.md)

## Run your own instance

The included Docker Compose stack supplies PostgreSQL, a Node service and optional Caddy HTTPS. Self-hosted mode enables all features without Stripe or an AllAuth subscription. You operate hosting, backups and updates and configure your email/OAuth/storage providers. Follow the [self-hosting guide](../../docs/SELF_HOSTING.md) for first-administrator creation and exact commands.

## Hosted plans

Free includes AllAuth attribution, up to 20 members per application end-user organization and five support impersonations per workspace per UTC calendar month. Pro is $9.99 USD per workspace per month plus applicable tax and removes attribution and those quotas, subject to fair use. A workspace covers its applications and Development/Production environments. Console teammates and application end-user organizations are different memberships.

## Authentication architecture

AllAuth React SDK 2.0.0 owns the client, components and signed proxy integration. Its package has zero Better Auth dependencies and works with the existing platform endpoints. Customers choose when to upgrade their applications. [Integration guide](INTEGRATION.md) · [SDK 2.0.0 release notes](https://allauth.co/releases/sdk-2-0-0)

The server dispatches authentication and session operations through an AllAuth interface backed by Better Auth. The project engine, hosted sign-in UI and shared OAuth/OIDC issuer still use Better Auth. [Engine interface](lib/auth-engine.ts) · [Server adapter](lib/legacy-auth-engine.ts) · [Provider inventory](PLUGINS.md)

## Source development

Use pnpm. Install and build the root packages, then install the separate service workspace with its frozen lockfile. The [self-hosting guide](../../docs/SELF_HOSTING.md#develop-from-source) describes local configuration. The service uses isolated PostgreSQL; public product pages render independently of account sessions.

```sh
pnpm --dir apps/auth typecheck
pnpm exec vitest run --root apps/auth --config vitest.config.ts lib/commercial/public-pages.test.ts lib/console/workspace-billing-render.test.ts
pnpm --dir apps/auth build
```

Run focused tests appropriate to each change. The SDK follows the immutable archive, version, checksum and notification requirements in `RELEASING.md`; existing integrations must remain compatible.

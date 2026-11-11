# AllAuth platform service

AllAuth provides hosted or self-hosted authentication, account security and organization management. The service lives in `apps/auth` and uses the Better Auth packages in this repository, with a React SDK and separate application environments.

The complete [platform source](https://github.com/allauth-co/allauth-platform) is available under the [MIT license](../../LICENSE.md). Better Auth, Better Auth UI and other third-party notices remain intact. Publishing source does not publish the SDK to a package registry or change retained release artifacts.

- [Self-hosting and recovery](../../docs/SELF_HOSTING.md)
- [Hosted plans](https://allauth.co/pricing)
- [React SDK quickstart](https://allauth.co/sdk/quickstart)
- [Release requirements](RELEASING.md)
- [Contributing](../../CONTRIBUTING.md) and [security reporting](../../SECURITY.md)

## Run your own instance

The included Docker Compose stack supplies PostgreSQL, a Node service and optional Caddy HTTPS. Self-hosted mode enables all features without Stripe or an AllAuth subscription. You operate hosting, backups and updates and configure your email/OAuth/storage providers. Follow the [self-hosting guide](../../docs/SELF_HOSTING.md) for first-administrator creation and exact commands.

## Hosted plans

Free includes AllAuth attribution, up to 20 members per application end-user organization and five support impersonations per workspace per UTC calendar month. Pro is $9.99 USD per workspace per month plus applicable tax and removes attribution and those quotas, subject to fair use. A workspace covers its applications and Development/Production environments. Console teammates and application end-user organizations are different memberships.

## Source development

Use pnpm. Install and build the root packages, then install the separate service workspace with its frozen lockfile. The [self-hosting guide](../../docs/SELF_HOSTING.md#develop-from-source) describes local configuration. The service uses isolated PostgreSQL; public product pages render independently of account sessions.

```sh
pnpm --dir apps/auth typecheck
pnpm exec vitest run --root apps/auth --config vitest.config.ts lib/commercial/public-pages.test.ts lib/console/workspace-billing-render.test.ts
pnpm --dir apps/auth build
```

Run focused tests appropriate to each change. The SDK follows the immutable archive, version, checksum and notification requirements in `RELEASING.md`; existing integrations must remain compatible.

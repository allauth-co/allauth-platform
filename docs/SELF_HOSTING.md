# Self-host AllAuth

Run the complete AllAuth platform with Node.js, PostgreSQL and your own domain. Self-hosted mode includes all features without an AllAuth subscription or Stripe configuration. You operate the service and pay infrastructure and provider costs. The [platform repository](https://github.com/allauth-co/allauth-platform) contains the service, required packages, tests and deployment files used in this guide.

## Docker Compose with HTTPS

Use a server with Docker Engine, Docker Compose v2 and OpenSSL. Point a domain you control, such as `auth.example.com`, at that server. Allow inbound TCP ports 80 and 443 for Caddy’s certificates and HTTPS; UDP 443 is optional for HTTP/3. Keep PostgreSQL private.

From the repository root:

```sh
cp deploy/self-host/.env.example .env.self-host
openssl rand -hex 32
openssl rand -hex 32
openssl rand -hex 32
```

Put the three independently generated values in `POSTGRES_PASSWORD`, `BETTER_AUTH_SECRET` and `SCIM_CREDENTIAL_HASH_SECRET`, respectively. The database password must be URL-safe; hex is suitable. Set `ALLAUTH_DOMAIN` to your real hostname, and set your application name and email sender. `.env.self-host` is excluded from Git. Restrict access to this file and retain a secure copy with your recovery material.

```sh
docker compose --env-file .env.self-host -f compose.self-host.yml config --quiet
docker compose --env-file .env.self-host -f compose.self-host.yml --profile https up --build -d
docker compose --env-file .env.self-host -f compose.self-host.yml ps
```

The app waits for PostgreSQL, runs versioned migrations and starts the service. Caddy obtains a certificate and forwards the verified client address using `X-Real-IP`. The app’s direct listener binds to loopback on port 3002 by default; the database has no public host port. Check `https://auth.example.com/api/health` using your hostname. For startup failures, inspect `docker compose --env-file .env.self-host -f compose.self-host.yml logs --tail 100 auth proxy`.

An existing reverse proxy can replace the optional Caddy profile. It must terminate HTTPS for the exact hostname and supply a verified client IP rather than trusting client-supplied forwarding headers. Keep `BETTER_AUTH_URL`, trusted origins and the passkey RP ID consistent. Do not expose the loopback app port directly as an HTTP production login endpoint.

## Create the first administrator

Do this before anyone creates an account. Initialisation requires explicit `self-hosted` mode and an empty, migrated user directory. It creates one verified administrator with a native password hash; it cannot overwrite accounts or reset passwords. It does not require an email provider.

In Bash or Zsh, enter a 12–128 character password at the hidden prompt. Replace the email and name. Pass the password only to this one-off container rather than storing it in the env file:

```sh
printf 'Initial administrator password: '
read -r -s ALLAUTH_INITIAL_ADMIN_PASSWORD
export ALLAUTH_INITIAL_ADMIN_PASSWORD
docker compose --env-file .env.self-host -f compose.self-host.yml run --rm --no-deps \
  -e ALLAUTH_INITIAL_ADMIN_EMAIL=operator@example.com \
  -e ALLAUTH_INITIAL_ADMIN_NAME=Operator \
  -e ALLAUTH_INITIAL_ADMIN_PASSWORD \
  auth node scripts/self-host/bootstrap.mjs
unset ALLAUTH_INITIAL_ADMIN_PASSWORD
```

Sign in at your auth domain, enable MFA and configure email. Initialisation refuses to run if users exist. For an existing directory, use `db:bootstrap-admin` from an installed source checkout to promote an existing verified, active account; do not remove accounts to repeat initialisation.

## Email, OAuth and optional services

Set `EMAIL_PROVIDER=resend`, `RESEND_API_KEY` and a verified-domain `EMAIL_FROM` to enable the included Resend transport. `EMAIL_FROM_NAME` is optional. This shared configuration serves platform email and projects without their own transport. Existing per-project overrides stay separate. Cloudflare email is also supported with its own credentials.

Without a sender, first-administrator creation works, but verification, recovery, magic-link, OTP and invitation email delivery does not. Verify an actual test message before relying on those flows. SMS delivery is not configured by this stack.

OAuth is optional. Register providers using your domains and keep credentials server-side. Platform Google uses `https://auth.example.com/api/auth/callback/google` with your hostname. Each application environment’s console setup guide supplies its own exact callbacks. Follow the [Apple](content/docs/integrations/allauth-tenant-apple.mdx) and [Microsoft](content/docs/integrations/allauth-tenant-microsoft.mdx) guides for environment-specific settings. Never reuse hosted AllAuth’s credentials or callbacks.

Branding uploads, owned avatars and customer custom-domain routing require their separately configured storage and gateways. They are optional and are not provisioned by Compose. Use your own resources; do not point a self-hosted instance at AllAuth’s hosted buckets or gateways. SSO and SCIM need the organization’s verified domain and configured identity provider.

## Connect an application

Create a workspace and application in your instance. The environment’s setup guide supplies the project slug, proxy secret, application origin and callbacks. Keep the proxy secret on your application server. Point the React SDK’s Next.js proxy at your instance:

```ts
import { createAllAuthProxy } from "@allauth/react/next";

const proxy = createAllAuthProxy({
  project: process.env.ALLAUTH_PROJECT!,
  proxySecret: process.env.ALLAUTH_PROXY_SECRET!,
  appOrigin: "https://app.example.com",
  allauthURL: "https://auth.example.com",
});
export const GET = proxy;
export const POST = proxy;
```

Use the documented catch-all route and matching provider and components. The browser talks to your application’s same-origin proxy. Follow the SDK v2 route and component examples with your instance URL. [React SDK quickstart](https://allauth.co/sdk/quickstart) · [Upgrade from v1](https://allauth.co/sdk/quickstart#upgrade)

Changing the auth origin requires reviewing callbacks, cookies and passkey RP IDs and does not transfer accounts or sessions automatically.

## Backups and recovery

Back up the entire PostgreSQL database, including `public` and every application schema. Save `.env.self-host`, separately managed keys and asset storage separately; a database dump does not include them.

```sh
mkdir -p output/self-host-backups
backupFile="output/self-host-backups/allauth-$(date -u +%Y%m%dT%H%M%SZ).dump"
docker compose --env-file .env.self-host -f compose.self-host.yml exec -T postgres \
  pg_dump -U allauth -d allauth -Fc > "$backupFile"
chmod 600 "$backupFile"
```

Restore into a separate recovery-check database, leaving the running database intact:

```sh
docker compose --env-file .env.self-host -f compose.self-host.yml exec -T postgres \
  createdb -U allauth allauth_restorecheck
docker compose --env-file .env.self-host -f compose.self-host.yml exec -T postgres \
  pg_restore -U allauth -d allauth_restorecheck --exit-on-error < "$backupFile"
```

Use a fresh name for later checks. Successful restore validates the dump, not every authentication flow. For a recovery drill, run an isolated app against the restored database with a separate test domain and no live outbound providers; check sign-in, memberships, sessions and migrations. Delete only recovery-check resources after verification. Keep backups encrypted and access-controlled because they contain authentication and personal data.

## Upgrades and rollback

1. Record the running source revision/image; take a verified backup and secure env/key copy.
2. Review release notes and compatibility requirements. Build and test the selected revision against an isolated restored database.
3. Rebuild with `docker compose --env-file .env.self-host -f compose.self-host.yml --profile https up --build -d`. Startup applies pending migrations and verifies existing SQL checksums.
4. Check health, administrator sign-in, a connected app, MFA, invitations and configured email delivery. Keep the previous image and recovery material until verified.

Do not edit applied SQL or invent destructive down-migrations. Reverting an image does not reverse database changes. Rollback requiring an older schema needs a coordinated restore of the matching database, configuration and app revision, accounting for writes since backup. Do not use `docker compose down -v` for routine upgrades; it removes persistent volumes.

## Develop from source

Use the repository’s Node version and pnpm 11.1.1. From the root:

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm --dir apps/auth install --frozen-lockfile
```

Copy `apps/auth/.env.example` to its ignored `.env.local`. Set an isolated PostgreSQL URL, independent secrets, `ALLAUTH_DEPLOYMENT_MODE=self-hosted`, `AUTH_RUNTIME=node`, and an exact loopback `ALLAUTH_AUTH_URL`, such as `http://localhost:3002`. Set `ALLAUTH_AUTH_SECRET` to a new random value for the local instance. Existing deployments can keep the `BETTER_AUTH_URL` and `BETTER_AUTH_SECRET` aliases and their existing values. Use the same trusted origin and `localhost` passkey RP ID. HTTP is loopback development only; deployed authentication requires HTTPS.

```sh
pnpm --dir apps/auth run db:migrate
AUTH_RUNTIME=node pnpm --dir apps/auth exec next dev -H localhost -p 3002
```

See [contributing](../CONTRIBUTING.md) for focused tests, typechecks and release gates. Self-hosting does not include an enterprise support or uptime commitment.

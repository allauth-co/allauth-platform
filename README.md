<img src="apps/auth/public/brand/allauth-icon.png" alt="AllAuth logo" width="112" height="112">

# AllAuth Platform

AllAuth provides authentication, account security and organization management with separate development and production environments. Use managed AllAuth or run the platform on your own infrastructure. [AllAuth website](https://allauth.co) · [Hosted plans](https://allauth.co/pricing)

- **Connect an application.** AllAuth React SDK 2.0.0 includes the React provider, components and signed Next.js proxy. It uses an AllAuth client and UI with zero Better Auth package dependencies. Existing v1 apps can continue using their pinned SDK. [Quickstart](https://allauth.co/sdk/quickstart) · [v2 upgrade guide](https://allauth.co/sdk/quickstart#upgrade) · [Immutable SDK release](https://github.com/allauth-co/allauth-sdk/releases/tag/v2.0.0)
- **Self-host AllAuth.** Run the service with Docker Compose, PostgreSQL and optional Caddy HTTPS. Self-hosted mode includes all features without a hosted subscription. [Self-hosting, backups and upgrades](docs/SELF_HOSTING.md)
- **Work on the platform.** The service lives in `apps/auth`. Its Dockerfile builds from the repository root. [Service overview](apps/auth/README.md) · [Contributing](CONTRIBUTING.md) · [Release requirements](apps/auth/RELEASING.md)

The platform source is available under the MIT license. The project authentication engine, hosted sign-in UI and shared issuer still use Better Auth. [MIT license](LICENSE.md) · [Third-party notices](THIRD_PARTY_NOTICES.md) · [Security reporting](SECURITY.md)

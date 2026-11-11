# AllAuth

AllAuth is an authentication platform with account security, organization management and separate application environments. Use the managed service at [allauth.co](https://allauth.co), or run the complete platform on your own infrastructure.

The complete [platform source](https://github.com/allauth-co/allauth-platform) is available under the [MIT license](LICENSE.md). Hosted Free includes AllAuth attribution, up to 20 members per end-user organization and five impersonations per workspace per UTC calendar month. Pro is $9.99 USD per workspace per month plus applicable tax and removes attribution and those quotas, subject to fair use. Self-hosted instances include all features without a hosted subscription.

- [Self-hosting, backups and upgrades](docs/SELF_HOSTING.md)
- [Service overview](apps/auth/README.md)
- [Hosted plans and limits](https://allauth.co/pricing)
- [Release requirements](apps/auth/RELEASING.md)
- [Public SDK source and immutable releases](https://github.com/allauth-co/allauth-sdk)
- [Contributing](CONTRIBUTING.md), [security reporting](SECURITY.md) and [third-party notices](THIRD_PARTY_NOTICES.md)

The service builds from the repository root using `apps/auth/Dockerfile`. Runtime credentials, customer data and private operational evidence do not belong in public source. SDK versions, tags, archives and checksums remain immutable.

The `packages/` tree contains the Better Auth framework used by the service.
Keep its package names, upstream attribution and licences intact. The original
Better Auth project overview follows below.

## Better Auth upstream

<div align="center">
  <picture>
    <source srcset="./banner-dark.png" media="(prefers-color-scheme: dark)"/>
    <source srcset="./banner-light.png" media="(prefers-color-scheme: light)"/>
    <img src="./banner-light.png" alt="Better Auth Logo"/>
  </picture>

  [![npm](https://img.shields.io/npm/dm/better-auth?style=flat&colorA=000000&colorB=000000)](https://npm.chart.dev/better-auth?primary=neutral&gray=neutral&theme=dark)
  [![npm version](https://img.shields.io/npm/v/better-auth.svg?style=flat&colorA=000000&colorB=000000)](https://www.npmjs.com/package/better-auth)
  [![GitHub stars](https://img.shields.io/github/stars/better-auth/better-auth?style=flat&colorA=000000&colorB=000000)](https://github.com/better-auth/better-auth/stargazers)

  <p>
    <a href="https://discord.gg/better-auth">Discord</a>
    ·
    <a href="https://better-auth.com">Website</a>
    ·
    <a href="https://github.com/better-auth/better-auth/issues">Issues</a>
  </p>
</div>

## Better Auth

Better Auth is a framework-agnostic authentication (and authorization) framework for TypeScript. It provides a comprehensive set of features out of the box and includes a plugin ecosystem that simplifies adding advanced functionalities with minimal code in a short amount of time. Whether you need 2FA, multi-tenant support, or other complex features, it lets you focus on building your actual application instead of reinventing the wheel.

### Why Better Auth

Authentication in the TypeScript ecosystem is a half-solved problem. Other open-source libraries often require a lot of additional code for anything beyond basic authentication. Rather than just pushing third-party services as the solution, I believe we can do better as a community—hence, Better Auth.

## Contribution

Better Auth is a free and open source project licensed under the [MIT License](./LICENSE.md). You are free to do whatever you want with it.

You could help continuing its development by:

- [Contribute to the source code](./CONTRIBUTING.md)
- [Suggest new features and report issues](https://github.com/better-auth/better-auth/issues)

## Security
If you discover a security vulnerability within Better Auth, please report it via [GitHub Security Advisories](https://github.com/better-auth/better-auth/security/advisories/new).

All reports will be promptly addressed, and you'll be credited accordingly.

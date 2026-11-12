# Contributing to AllAuth

This repository contains the AllAuth service in `apps/auth`, its self-hosting configuration, and the framework packages it builds on. Please follow the [code of conduct](CODE_OF_CONDUCT.md).

## Report an issue

- For AllAuth platform bugs, search [existing issues](https://github.com/allauth-co/allauth-platform/issues), then open a [bug report](https://github.com/allauth-co/allauth-platform/issues/new?template=bug_report.yml) with the affected version or commit and steps to reproduce it.
- For feature requests, describe the problem, who it affects and what would solve it in the [AllAuth Platform issue tracker](https://github.com/allauth-co/allauth-platform/issues).
- For bugs in the React SDK or its Next.js proxy, use the [AllAuth SDK issue tracker](https://github.com/allauth-co/allauth-sdk/issues).
- For suspected vulnerabilities, follow the private reporting instructions in the [AllAuth security policy](SECURITY.md).

## Develop locally

Fork and clone [AllAuth Platform](https://github.com/allauth-co/allauth-platform). Use the Node.js version in [`.nvmrc`](.nvmrc) and the pnpm version in [`package.json`](package.json). From the repository root, install and build the framework packages, then install the service workspace.

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm --dir apps/auth install --frozen-lockfile
```

Configure isolated local services using the [self-hosting development guide](docs/SELF_HOSTING.md#develop-from-source).

## Test and document changes

Run focused Vitest tests for the paths you changed. New features need tests. For a bug fix, confirm the intended behavior, then add a failing regression test before changing the implementation.

```sh
pnpm exec vitest run --root apps/auth --config vitest.config.ts lib/commercial/public-pages.test.ts
pnpm typecheck
pnpm --dir apps/auth typecheck
pnpm --dir apps/auth build
```

Keep SDK requests, cookies, proxy signatures and authentication behavior compatible. Update the relevant public documentation for API changes and follow the [release guide](apps/auth/RELEASING.md) for versioned SDK artifacts.

## Work on the framework packages

The framework in `packages/` comes from Better Auth. Keep upstream package names, copyright and attribution intact. See the [third-party notices](THIRD_PARTY_NOTICES.md).

For changes to framework tests, use `getTestInstance()` from `better-auth/test` and pass client plugins through `clientOptions.plugins`. Adapter tests use Docker and end-to-end suites live in `e2e/`. Add a changeset with `pnpm changeset` for changes to released framework packages. See the [upstream contribution guide](https://github.com/better-auth/better-auth/blob/main/CONTRIBUTING.md).

If a bug reproduces in unmodified Better Auth, report it through the [upstream issue tracker](https://github.com/better-auth/better-auth/issues).

## Open a pull request

Target `main`. Use a [Conventional Commits](https://www.conventionalcommits.org/) title, such as `fix(console): keep workspace selection on refresh`. Describe the change, link related issues, list the checks you ran and call out any compatibility impact. Include screenshots for visible UI changes.

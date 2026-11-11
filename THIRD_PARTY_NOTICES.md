# Third-party notices

The root MIT license grants rights to AllAuth-owned code and preserves the Better Auth copyright notice. It does not relicense every dependency or bundled asset as MIT. Third-party code retains its own copyright, license and distribution requirements.

- The `packages/` framework comes from [Better Auth](https://github.com/better-auth/better-auth); preserve its MIT license, copyright and attribution.
- The vendored Better Auth UI registry retains [its MIT notice](apps/auth/components/better-auth-ui/LICENSE), [its attribution](apps/auth/components/better-auth-ui/ATTRIBUTION.md) and [the shadcn MIT notice](apps/auth/components/better-auth-ui/ui/LICENSE).
- Runtime dependencies include MIT, Apache-2.0, BSD, ISC, font and other licenses. Preserve package license/notice files and the notices emitted by bundled utility builds. The [plugin inventory](apps/auth/PLUGINS.md) records the evidence and activation state of provider integrations.
- Sharp's platform-specific image-processing binaries include libvips and carry their own notices and licensing, including LGPL-3.0-or-later for the applicable packaged libvips binary. Preserve the notices and satisfy the corresponding license/source and redistribution requirements for the exact native packages you distribute. Linux container builds may include a different platform binary from a developer's machine; check that shipped package rather than assuming the macOS inventory applies.

Self-hosted distributions and container images must retain the notices for their actual included dependency versions. An MIT license on AllAuth does not remove obligations for packaged native libraries, external assets or provider SDKs.

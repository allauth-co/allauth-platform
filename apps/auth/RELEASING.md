# AllAuth release pathway

Every SDK and platform publication must use this pathway. Customer repositories are not required to announce updates, and existing integrations must remain compatible.

1. Write factual public release notes before publishing. Describe the change, compatibility, upgrade steps and known limitations. Add a permanent `/releases/<slug>` entry. Record an original publication date only when supported by release evidence; label reconstructed history and leave unknown dates unknown.
2. For an SDK change, increment the package version. Run `pnpm --dir apps/auth run sdk:pack`. Never overwrite an existing archive, version or Git tag. Keep old download URLs available.
3. Publish the SDK-only source to `https://github.com/allauth-co/allauth-sdk`, using the matching `v<version>` tag. Attach the exact archive and SHA-256 file to its immutable GitHub release. Keep platform source in its separate platform release rather than adding it to an SDK-only artifact. Never include customer data, credentials or private fixtures in either publication.
4. Keep the SDK catalog, archive checksums, public source/tag links and release assets aligned. Every archive in `public/sdk/integrity.json` needs public release notes. Run `pnpm --dir apps/auth run verify:public-sdk-releases` before publishing the service catalog; it rejects unpublished or mutable GitHub releases, mismatched archive/checksum bytes and removal of already-public SDK versions. Historical backfills must have `announce: false` and must not generate retrospective email or unread announcements.
5. Run the installed-client request checks, archived-client compatibility matrix, release-catalog checks, focused feature tests and typechecks. Build the application. New fields and version reports remain optional; metadata recording must never delay or fail authentication.
6. Publish the public SDK pages, release notes, feeds and sitemap with the platform release. Include the release in public navigation. Preserve existing permalink and download URLs.
7. Announce new SDK and platform releases through the account notification centre and durable email queue. Respect verified workspace-manager eligibility and email preferences. Do not require knowledge of a customer's installed SDK version or access to their source code.
8. Verify the public notes and exact download bytes, authenticated notification UI, relevant existing integrations and email processing. Distinguish provider acceptance from confirmed inbox delivery. Save a release receipt and source/artifact checksums.

Public SDK source and artifacts are versioned separately from the platform service. The complete MIT-licensed platform source is published separately at `https://github.com/allauth-co/allauth-platform`. Verify public source availability, its exact revision and the deployment guide before recording a platform source publication as complete. Preserve upstream and third-party notices. Publishing source does not publish an npm package or alter historical SDK package metadata, licences, archives or tags.

Current repository links use the `allauth-co` organisation. An ownership transfer does not rewrite retained release source URLs, tag links, archive URLs, checksums or operational receipts. The publication gate checks the canonical repository while accepting the exact retained repository URL for historical release metadata.

For platform source publication, prepare a reviewed export containing the service, required packages, tests and self-host deployment files. Exclude secrets, private operational evidence, customer fixtures and account-specific deployment configuration. Use the public service overview instead of internal operations notes. Public CI must be independent of production credentials and package-publishing workflows. Verify a clean install/build and self-hosting instructions before recording publication as complete.

During SDK development, pack to a local directory outside `public/sdk` and run `pnpm --dir apps/auth verify:sdk-artifact --candidate /absolute/path/to/archive.tgz`. The platform build verifies the served SDK separately. Keep `lib/published-sdk.json` on the manifest of the current served archive until its replacement passes the release gates. Mark major SDK upgrades `migration-required` and link the upgrade instructions before enabling announcements.

## Release checks

```sh
pnpm --dir apps/auth run check:sdk
pnpm --dir apps/auth run verify:sdk-artifact
pnpm --dir apps/auth run verify:public-sdk-releases
pnpm --dir apps/auth typecheck
pnpm --dir apps/auth build
```

Run focused notification/API/UI tests for notification changes. SDK release notes must be supported by the tagged source and exact artifact; do not infer deployment, adoption, delivery or indexing outcomes from a build or publication alone.

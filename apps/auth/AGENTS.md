<!-- BEGIN:nextjs-agent-rules -->

# This is NOT the Next.js you know

This version has breaking changes — APIs, conventions, and file structure may all differ from your training data. Read the relevant guide in `node_modules/next/dist/docs/` (resolved from this file's directory; in monorepos the `next` package may not be visible from the repo root) before writing any code. Heed deprecation notices.

This block is written and re-added by `next dev` — verify at `node_modules/next/dist/server/lib/generate-agent-files.js`. Removing it from a diff only re-creates the uncommitted change; committing it with your work keeps the tree clean.

<!-- END:nextjs-agent-rules -->

## AllAuth compatibility and releases

- Backward compatibility is a release requirement. Keep existing SDK request, cookie, proxy-signature and authentication contracts working. Add optional capabilities; never require SDK-version reporting to authenticate.
- Published `public/sdk/*.tgz` files are immutable. Use a new SDK version and `pnpm --dir apps/auth run sdk:pack`; never replace a previous release to deliver a fix.
- Run `pnpm --dir apps/auth run check:sdk` and `pnpm --dir apps/auth run verify:sdk-artifact`. The service build also checks actual client request behaviour, archived-client transport compatibility, archive integrity and matching release-notification metadata.
- Keep new release notes and the notification catalog aligned with the default SDK version and its exact archive checksum. Update notices and email delivery must work without access to customer repositories.
- Every SDK and platform publication follows `RELEASING.md`: public notes and permanent URLs, public SDK source/tags/assets, compatibility checks, notification preferences and a verified release receipt. Run `verify:public-sdk-releases` before publishing the service's matching SDK catalog. Historical backfills never announce themselves.
- SDK observations are advisory. Unknown versions stay unknown; recording failures must not delay or fail authentication. Customer dependency upgrades remain explicit actions in their own applications.

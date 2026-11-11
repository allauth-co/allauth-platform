# Application branding

Application Settings in the AllAuth console controls the shared name, support email, light/dark logo, favicon, accent colors and AllAuth attribution. Development and production environments in the same application use one versioned settings record. User databases and authentication policies remain separate.

`GET /api/admin/application-settings?project=<slug>` returns the current settings and actual upload availability. `PATCH` accepts the complete `{version, branding}` object. A stale version returns HTTP 409 with `Application settings changed. Reload before saving.` Reload before retrying a conflicting edit.

These console endpoints accept a fresh verified platform cookie. Workspace owners/administrators and platform administrators can manage the selected application; tenant administrator roles do not grant console access. Writes require the exact AllAuth origin. Workspace/application identifiers come from the selected project registry row, rather than request bodies.

`POST /api/admin/application-settings/assets?project=<slug>` accepts multipart `kind` (`logo`, `logoDark`, or `favicon`), one `file`, and an optional `version`. Logos support PNG, JPEG and WebP; favicons support PNG and ICO. File bytes and the declared MIME must agree. Files are limited to 2 MiB, and the request stream is bounded before multipart parsing. SVG and GIF uploads are unavailable.

Uploads return `{url, settings}` and update only the chosen saved branding field. Settings and the audit event commit together after a fresh permission/version check. Unsaved changes in other form fields can still be saved separately using the returned version. Removing an image saves `null`; existing immutable asset versions remain in storage.

Storage uses `ALLAUTH_ASSET_ORIGIN` (default `https://assets.allauth.co`) and a private `ALLAUTH_ASSET_SECRET` of at least 32 characters. The signed Worker upload envelope binds method, exact application/workspace object path, MIME, timestamp and SHA-256 body digest. It expires after 60 seconds. The server never sends the credential to the browser. Uploaded images are public immutable objects; storage does not expose a bucket listing.

Native project `GET /sdk/config` includes public `branding`. Each request reads the shared settings afresh, so saved presentation changes do not require an auth-instance rebuild. Its existing provider/plugin capability fields are preserved. Public configuration contains no session, credential, schema or private workspace data.

Migration `011-application-branding.sql` runs only in the platform schema. Existing applications receive one initial record, preferring the production environment's name. New applications use the same defaults until their first settings write. Both normal tenant migration and new tenant provisioning skip this platform migration.

Hosted account pages also read the shared branding through the verified hosted-domain binding. They use the managed logos, support/attribution settings, accent colors and browser icon. The AllAuth platform keeps its own branding. Embedded widgets expose the favicon configuration without changing the embedding application’s browser metadata.

Authentication emails read the selected application's saved branding on every send, including through cached authentication instances. Verification, password reset, email change, account deletion, sign-in links, email codes, new-device notifications and organization invitations use its current name, light logo, primary colour, support email and attribution setting. Development and production use the same application branding. When no logo is saved, emails show the application's name; they never substitute another application's assets. Email-compatible HTTPS raster images and inline styling provide a readable light layout and a plain-text alternative.

AllAuth account emails and workspace team invitations use the AllAuth logo and colours. Delivery continues through the configured, verified Cloudflare sender domain; an application's branding does not authorize sending from its support email or domain.

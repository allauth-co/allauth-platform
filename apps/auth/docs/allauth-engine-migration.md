# AllAuth engine migration

The project migration uses the existing PostgreSQL schemas, project IDs, key derivation and auth URLs. The React SDK and signed app proxy can be upgraded separately. Production project requests and the shared issuer still use the existing engine.

## Verify in a development realm

Use an isolated PostgreSQL database, synthetic accounts and the verified accounts hostname for a development project. Add its immutable project ID from the registry to either setting. Both settings accept a comma-separated list of development project IDs and default to empty.

| Setting | Effect |
| --- | --- |
| `ALLAUTH_PROJECT_SESSION_SHADOW_IDS` | Compare the authenticated principal from successful project session responses with the AllAuth SQL reader. The comparison cannot authorize a request or change its response. |
| `ALLAUTH_PROJECT_HOSTED_UI_PROJECT_IDS` | Show the AllAuth React forms on the verified project accounts hostname. The forms use the existing authentication engine, including its session, broker and MFA handling. |

Use the hosted preview to exercise password sign-in, registration, password recovery, available social sign-in and passkeys. The preview keeps signed OAuth continuations and existing alternate sign-in pages on the current hosted UI. It only rewrites the known hosted MFA continuation into the SDK's challenge response. Clear a project's ID from either setting to disable the corresponding preview.

The session comparison emits only the project ID and the result `match`, `different` or `unavailable`. A revocation that commits between the two reads can produce a difference. Review unexplained differences in the isolated fixture before using the reader for authorization.

## Project cutover

- The AllAuth engine candidate exercises password sign-in, session reads and refresh, sign-out and scoped session revocation. It uses the existing cookie format, scrypt and imported Clerk bcrypt credentials. It remains an isolated fixture engine while additional policies and flows are ported. The password reset consumer accepts legacy-issued links and can revoke existing project sessions, grants and outstanding authentication challenges in the same transaction as the password change.
- The first-party storage and verification code reads encrypted legacy MFA data and uses rollback-compatible recovery-code writes. The passkey verifier uses SimpleWebAuthn with the existing credential IDs, public keys, counters, relying-party IDs and origin checks.
- Complete project account linking, configured OAuth and enterprise flows, MFA enrolment and challenges, passkey session issuance, organization and invitation flows, and support access. Verify hook behavior, authorization, tenant isolation, rate limits, auditing and all linked session/grant revocations. Identify configured users and support obligations before retiring any integration.
- Test archived v1 clients and SDK v2 with both engines, including custom domains, in-flight callbacks and challenges. Rehearse switching back after session issuance, password changes, recovery-code consumption and grant revocation. Run the Railway and self-hosted Docker upgrade checks against an isolated restored database.
- Select realms by immutable project ID and keep one authoritative writer in each. Start with internal development projects and advance only after compatibility, isolation and rollback pass. Compare aggregate sign-in, callback and refresh outcomes and latency before expanding a cohort.

## Shared issuer cutover

After project cohorts pass, replace the shared issuer as a unit. Keep the issuer and endpoint URLs, client registrations, subjects, claims, signing keys, consent, grant lifetimes, refresh rotation, revocation and approved device flows. Test token and grant continuity across cutover and rollback. Run the OpenID Provider conformance suite and an independent security review before switching the shared issuer.

Remove the old engine, UI, packages and build tooling from the current distribution after the rollback window. Keep the readers required for existing data, upstream attribution and immutable SDK releases.

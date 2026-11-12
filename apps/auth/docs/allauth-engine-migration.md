# AllAuth engine migration

The project migration uses the existing PostgreSQL schemas, project IDs, key derivation and auth URLs. The React SDK and signed app proxy can be upgraded separately. Production project requests and the shared issuer still use the existing engine.

## Verify in a development realm

Use an isolated PostgreSQL database, synthetic accounts and the verified accounts hostname for a development project. Add its immutable project ID from the registry to either setting. Both settings accept a comma-separated list of development project IDs and default to empty.

| Setting | Effect |
| --- | --- |
| `ALLAUTH_PROJECT_SESSION_SHADOW_IDS` | Compare the authenticated principal from successful project session responses with the AllAuth SQL reader. The comparison cannot authorize a request or change its response. |
| `ALLAUTH_PROJECT_HOSTED_UI_PROJECT_IDS` | Show the AllAuth React forms on the verified project accounts hostname. The forms use the existing authentication engine, including its session, broker and MFA handling. |

Use the hosted preview to exercise email and username password sign-in, registration, password recovery, email links and codes, organization sign-in, configured social providers and passkeys. The dedicated MFA form supports authenticator and recovery codes and the existing trusted-device choice. Signed OAuth and broker handoffs continue through the current hosted UI. Clear a project's ID from either setting to disable the corresponding preview.

The session comparison emits only the project ID and the result `match`, `different` or `unavailable`. A revocation that commits between the two reads can produce a difference. Review unexplained differences in the isolated fixture before using the reader for authorization.

## Project cutover

- The AllAuth engine candidate covers password sign-in by email or username, registration, password recovery, email verification, session refresh and scoped session revocation in fixtures. Existing scrypt and Clerk bcrypt credentials still verify. Password recovery consumes legacy links and revokes project sessions, grants and outstanding challenges in the same transaction as the password change.
- TOTP, recovery codes and trusted devices use existing project records and signed cookies. MFA enrolment and disable rotate the session and revoke sibling sessions and grants on a policy transition. Passkey HTTP ceremonies use SimpleWebAuthn with the existing credential IDs, counters, relying-party IDs and origins. PostgreSQL tests switch engines mid-ceremony and verify that the resulting session survives rollback.
- Magic links and sign-in codes consume the existing verification records, and both engines can complete an email proof issued by the other. The AllAuth sign-in authority requires an enrolled second factor before creating a session. Stored project domain and IP rules, credential-failure counters, and known-device cookies use the existing PostgreSQL records.
- The project OAuth client exchanges codes with the existing AllAuth broker and configured Google clients. Fixtures verify pending broker callbacks across both engines and check that linked accounts retain their existing user IDs. Broker and Google account linking and unlinking use the live project session. Organization creation, permission checks, active membership and invitation creation, acceptance and cancellation use the existing organization and session rows.
- The read-only enterprise catalog counts stored SSO provider, SCIM credential and directory binding states in a single project schema. It reports configured records and credential expiry without exposing customer IDs or secrets. Exercise configured connectors with the current writer before changing a realm.
- Candidate logout revokes session-bound access and online refresh grants in the session deletion transaction. Offline refresh grants survive as before. Realms with back-channel delivery requirements still need the current engine.
- Complete the remaining account management and linking routes, configured providers, enterprise SSO and SCIM, organization administration, support access, and connected-app logout and revocation. Verify authorization, isolation, rate limits and audit events across those flows. The hosted preview uses the existing engine for its full set of sign-in options.
- Test archived v1 clients and SDK v2 with both engines, including custom domains, in-flight callbacks and challenges. Rehearse switching back after session issuance, password changes, recovery-code consumption and grant revocation. Run the Railway and self-hosted Docker upgrade checks against an isolated restored database.
- Select realms by immutable project ID and keep one authoritative writer in each. Start with internal development projects and advance only after compatibility, isolation and rollback pass. Compare aggregate sign-in, callback and refresh outcomes and latency before expanding a cohort.

## Shared issuer cutover

After project cohorts pass, replace the shared issuer as a unit. Keep the issuer and endpoint URLs, client registrations, subjects, claims, signing keys, consent, grant lifetimes, refresh rotation, revocation and approved device flows. Test token and grant continuity across cutover and rollback. Run the OpenID Provider conformance suite and an independent security review before switching the shared issuer.

Remove the old engine, UI, packages and build tooling from the current distribution after the rollback window. Keep the readers required for existing data, upstream attribution and immutable SDK releases.

# Project Agent Auth compatibility

The platform installs `@better-auth/agent-auth` 0.6.2. The endpoint inventory below comes from the installed package’s endpoint map and the AllAuth configuration in `lib/features/server.ts`. Paths are relative to the selected project auth base. AllAuth registers the agent device-code handler under a distinct endpoint key so `/agent/device/code` and OAuth `/device/code` continue to dispatch separately.

| Installed surface | Methods and paths | Owned fixture coverage |
| --- | --- | --- |
| Discovery | `GET /agent-configuration` | Pending |
| Host listing and detail | `GET /host/list`, `GET /host/get` | Signed browser session |
| Host revocation | `POST /host/revoke` | Fresh verified owner cookie or signed self-revocation by an active owned inline Ed25519 host. |
| Host provisioning and enrollment | `POST /host/create`, `POST /host/enroll` | Fresh verified browser provisioning, inline Ed25519, and one-time enrollment across writers. |
| Host update | `POST /host/update` | Fresh verified browser owner can edit the host and replace its inline key under the existing ID. |
| Signed host key rotation | `POST /host/rotate-key` | Active owned inline host with an exact host-ID issuer and unused JTI. Host-ID changes require a host without linked agents or approvals. |
| Host account switch | `POST /host/switch-account` | Pending |
| Delegated registration | `POST /agent/register` | Existing active owned host with a verified inline Ed25519 JWT and one-time JWT ID. The agent starts active with an empty capability budget. |
| Agent identity transfer | `POST /agent/claim` | Pending. |
| Agent session | `GET /agent/session` | Verified active inline delegated agent, live grants, and an explicit public user projection. |
| Agent introspection | `POST /agent/introspect` | Inline delegated agent JWT in the `token` body field, with the native compact public claims and replay checks. |
| Signed agent status | `GET /agent/status` | Known inline Ed25519 host or active delegated agent. Keeps native status and grant fields and the normal active-agent heartbeat. |
| Agent listing and detail | `GET /agent/list`, `GET /agent/get` | Current owner’s signed browser session. |
| Agent profile | `POST /agent/update` | Current agent owner’s signed browser session, with native name and metadata updates. |
| Agent revocation | `POST /agent/revoke` | Signed browser session of the agent or host owner, or an active signed host selecting an agent on that host. Direct agent JWT revocation is pending. |
| Agent expiry cleanup | `POST /agent/cleanup` | Live browser owner can expire their overdue active agents and pending approval records. |
| Agent reactivation | `POST /agent/reactivate` | Active signed host and eligible owner, existing delegated inline agent, and empty host defaults for expired-agent renewal. |
| Agent key rotation | `POST /agent/rotate-key` | Pending. |
| Browser approvals | `GET /agent/ciba/pending`, `POST /agent/approve-capability` | Current owner’s pending device and CIBA summaries. Fresh verified owner can approve or deny an existing, owner-bound delegated registration without capability grants. The decision accepts native `approval_id` or `agent_id`. |
| Capability grant revocation | `POST /agent/revoke-capability` | Fresh verified browser owner, active signed host, or active signed agent can revoke named existing grants within their scope. |
| Agent approval requests and grants | `POST /agent/request-capability`, `POST /agent/grant-capability`, `POST /agent/ciba/authorize`, `POST /agent/device/code` | Pending |
| Capability catalog | `GET /capability/list`, `GET /capability/describe` | A live signed host or agent can read the configured empty catalog. |
| Capability actions | `POST /capability/execute`, `POST /capability/batch-execute` | Pending. AllAuth denies execution. |

AllAuth permits delegated registration with inline Ed25519 public keys. It disables dynamic hosts and remote key discovery, limits each account to five agents, and configures a 15-minute session, a one-hour agent maximum lifetime, and a 24-hour absolute lifetime. Browser host writes require a verified non-impersonated session created within five minutes and exact user ownership. The installed package distinguishes `host+jwt` from `agent+jwt` and checks replay in a process-local cache. The verified hosted gateway currently forwards Authorization only for its separate OAuth and SCIM allowlists. The package’s description mentions a well-known discovery alias. The application installs the auth-relative `/agent-configuration` route.

## Persisted state

The existing project schema in `migrations/005-free-plugins.sql` carries all four Agent Auth tables. Existing IDs and row formats remain in place.

| Table | Compatibility requirements |
| --- | --- |
| `agentHost` | Exact host ID and nullable owner, JSON text for default capabilities and inline public JWK, key ID, enrollment-token hash and expiry, and activation, use and expiry timestamps. Statuses are `active`, `pending`, `pending_enrollment`, `revoked` and `rejected`. Enrollment hashes are base64url-encoded SHA-256. |
| `agent` | Exact agent ID, nullable owner, host foreign key, mode, public JWK text and key ID, metadata text and lifecycle timestamps. Statuses are `active`, `pending`, `expired`, `revoked`, `rejected` and `claimed`. |
| `agentCapabilityGrant` | Exact agent ID and capability, grant/deny actor IDs, expiry and constraints text. Statuses are `active`, `pending`, `denied`, `revoked` and `consumed`. |
| `approvalRequest` | Approval ID, `device_authorization` or `ciba` method, nullable agent, host and user references, capabilities text, hashed user code, polling and expiry state, and CIBA delivery fields. Statuses are `pending`, `approved`, `denied` and `expired`. Keep these records separate from OAuth `deviceCode`. |

The owned fixture reads the original host rows and preserves the legacy public response. Browser revocation updates the host, its eligible agents and their grants in one realm-scoped transaction. An already-revoked host returns zero newly revoked agents. Enrollment preserves the one-hour token deadline, the 15-minute host session lifetime and the host ID on activation. Both writers consume tokens issued by the other. Same-owner key enrollment can merge a pending host into an existing host and retire the pending record. The fixture requires a valid public Ed25519 JWK and refuses unowned or ambiguous key records.

The native pending list accepts a current browser session and scopes rows by owner. The decision endpoint confirms a fresh verified browser session and matches the approval, delegated agent and existing active host to that owner. Device approval checks the existing hashed code. Decisions resolve compatible pending rows and the agent status in one transaction. There is no separate browser approval lookup route. The fixture leaves unbound requests, host transfers, mixed approval methods, capability grants and push delivery outside its decision scope.

Signed status accepts a host ID or unique key ID and scopes the requested agent to that host. Agent credentials resolve their own subject, validate the configured audience and any native request binding, and consume the JWT ID once in the selected realm. PostgreSQL retains the replay check across owned process restarts. Status refreshes the agent’s 15-minute heartbeat within the one-hour activation and 24-hour absolute limits. Host polling stays repeatable as in the native route. The fixture excludes ambiguous keys, remote key records, transparent reactivation and browser fallback. The production factory retains its exclusion for projects with agent hosts. Hosted bearer transport and the remaining signed operations and approval flows still require compatibility proof before that exclusion changes.

Delegated registration binds the new agent to the same owner and host, retains its inline public key and native 15-minute lifetime, and updates the host heartbeat on success. The fixture serializes the five-active-agent limit across an owner’s hosts and consumes registration JWT IDs separately from repeatable host status reads. Legacy reads recognize the owned rows. Forced or pending enrollment and registration retries that create a new approval remain outside this slice.

Browser agent list and detail accept the current owner’s signed session and expose the native grant projections. List preserves status, mode, and host filters and pagination. Browser revocation locks the live session and target authority, clears the agent’s inline signing key and key ID, and revokes its grants in one realm-scoped transaction. The persisted host owner can revoke an agent on that host even when the agent is unbound. The installed client’s disconnect operation uses an active signed host and an explicit agent ID. This operation remains repeatable under the same valid host proof and leaves the host and other agents usable. Legacy reads after rollback recognize the updated rows.

Browser profile updates require the agent owner’s live session. The native metadata map accepts string, number, boolean and null values. A supplied map replaces the stored map, and a request containing only the name retains the previous metadata. The write changes the profile and update time under the same agent ID.

Browser cleanup changes due active agents and due pending approvals for the signed owner to `expired`, using one transaction and the existing five-per-minute limit. The native response counts each transition. Expired agent rows retain their signing keys and grants for the separate reactivation flow.

Explicit reactivation verifies the same host’s existing signed key and locks its eligible owner and delegated agent. With empty host defaults, it clears old grant rows and starts a new 15-minute agent session under the existing ID and key. A repeat on an active agent reads the existing session. The absolute lifetime retires an expired agent’s key and grants. Reactivation with configured capabilities or approval requirements still needs separate coverage.

Capability revocation accepts the fresh verified browser owner of the agent or its persisted host, a live signed host selecting one of its agents, or a live agent selecting itself. It changes every matching existing grant and returns the changed capability names and grant IDs. Agent credentials require the native audience and single-use JTI and validate any supplied method, URL and JSON body binding. An authorized retry with a fresh agent credential returns empty change lists.

Signed host self-revocation verifies the active host’s existing inline key, accepts its exact ID or an unambiguous key ID as the issuer, and applies the same grant cascade as browser revocation. Successful revocation clears the verifying key. A retry using that key receives the native authentication error, including after rollback. The fixture covers direct requests to the selected realm.

Browser host update replaces the inline Ed25519 key under the original host ID and preserves existing agent and approval links. The candidate rejects a key ID already assigned to another host or matching another host ID. The native and owned engines accept each other’s replacement keys and reject the previous key after a successful write.

Signed host rotation uses the replacement JWK thumbprint as the host ID. The installed route’s issuer lookup requires the existing host ID. A client using the key ID as its issuer can rotate through this route when those IDs match. PostgreSQL’s agent and approval foreign keys prevent changing the ID of a referenced host. The fixture reports that conflict before writing and supports same-ID key metadata updates under the same authorization.

Capability catalog reads preserve the native empty list and unknown-capability response. Both require a live signed host or delegated agent in the selected realm. Agent credentials share the same single-use proof records and bounded heartbeat as signed status. Host credentials remain reusable for catalog reads within their existing lifetime.

Introspection validates the body token against the active agent’s stored inline key and returns the native identity, stored expiry and currently active grants. It preserves legacy body tokens with optional audience and JTI claims. A supplied audience must match a native audience for the selected realm, and a supplied JTI shares the persisted replay check with status and catalog reads. The fixture accepts a single credential in the request body.

The installed session endpoint returns its adapter user object inside the Agent Auth session. The owned fixture selects AllAuth’s public project-user fields for the verified agent’s active owner. The projection excludes private metadata, directory management fields and moderation details. The endpoint retains the native public agent, host and grant shape, including JWT grant filtering, and renews the bounded agent heartbeat. A browser cookie or valid host proof alone returns the native empty session.

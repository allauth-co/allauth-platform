# Project Agent Auth compatibility

The platform installs `@better-auth/agent-auth` 0.6.2. The endpoint inventory below comes from the installed package’s endpoint map and the AllAuth configuration in `lib/features/server.ts`. Paths are relative to the selected project auth base. AllAuth registers the agent device-code handler under a distinct endpoint key so `/agent/device/code` and OAuth `/device/code` continue to dispatch separately.

| Installed surface | Methods and paths | Owned fixture coverage |
| --- | --- | --- |
| Discovery | `GET /agent-configuration` | Pending |
| Host listing and detail | `GET /host/list`, `GET /host/get` | Signed browser session |
| Host revocation | `POST /host/revoke` | Fresh verified owner cookie. Signed host revocation is pending. |
| Host provisioning and enrollment | `POST /host/create`, `POST /host/enroll` | Fresh verified browser provisioning, inline Ed25519, and one-time enrollment across writers. |
| Host maintenance | `POST /host/update`, `POST /host/rotate-key`, `POST /host/switch-account` | Pending |
| Delegated registration | `POST /agent/register` | Existing active owned host with a verified inline Ed25519 JWT and one-time JWT ID. The agent starts active with an empty capability budget. |
| Agent identity and transfer | `POST /agent/claim`, `GET /agent/session`, `POST /agent/introspect` | Pending |
| Signed agent status | `GET /agent/status` | Known inline Ed25519 host or active delegated agent. Keeps native status and grant fields and the normal active-agent heartbeat. |
| Browser agent lifecycle | `GET /agent/list`, `GET /agent/get`, `POST /agent/revoke` | Signed browser session. List and detail are owner-scoped. Revocation also accepts the persisted host owner. |
| Other agent lifecycle | `POST /agent/update`, `POST /agent/rotate-key`, `POST /agent/reactivate`, `POST /agent/cleanup` | Pending, along with signed machine use of `/agent/revoke`. |
| Browser approvals | `GET /agent/ciba/pending`, `POST /agent/approve-capability` | Current owner’s pending device and CIBA summaries. Fresh verified owner can approve or deny an existing, owner-bound delegated registration without capability grants. The decision accepts native `approval_id` or `agent_id`. |
| Agent approval requests and grants | `POST /agent/request-capability`, `POST /agent/grant-capability`, `POST /agent/revoke-capability`, `POST /agent/ciba/authorize`, `POST /agent/device/code` | Pending |
| Capability catalog and actions | `GET /capability/list`, `GET /capability/describe`, `POST /capability/execute`, `POST /capability/batch-execute` | Pending. AllAuth has an empty catalog and denies execution. |

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

Browser agent list and detail accept the current owner’s signed session and expose the native grant projections. List preserves status, mode, and host filters and pagination. Browser revocation locks the live session and target authority, clears the agent’s inline signing key and key ID, and revokes its grants in one realm-scoped transaction. The persisted host owner can revoke an agent on that host even when the agent is unbound. Legacy reads after rollback recognize the updated rows. Machine-authorized revocation still requires separate coverage.

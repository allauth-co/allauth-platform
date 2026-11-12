# Project Agent Auth compatibility

The platform installs `@better-auth/agent-auth` 0.6.2. The endpoint inventory below comes from the installed package’s endpoint map and the AllAuth configuration in `lib/features/server.ts`. Paths are relative to the selected project auth base. AllAuth registers the agent device-code handler under a distinct endpoint key so `/agent/device/code` and OAuth `/device/code` continue to dispatch separately.

| Installed surface | Methods and paths | Owned fixture coverage |
| --- | --- | --- |
| Discovery | `GET /agent-configuration` | Pending |
| Host listing and detail | `GET /host/list`, `GET /host/get` | Signed browser session |
| Host revocation | `POST /host/revoke` | Fresh verified owner cookie. Signed host revocation is pending. |
| Host provisioning and enrollment | `POST /host/create`, `POST /host/enroll` | Fresh verified browser provisioning, inline Ed25519, and one-time enrollment across writers. |
| Host maintenance | `POST /host/update`, `POST /host/rotate-key`, `POST /host/switch-account` | Pending |
| Agent identity | `POST /agent/register`, `POST /agent/claim`, `GET /agent/session`, `POST /agent/introspect` | Pending |
| Agent lifecycle | `GET /agent/list`, `GET /agent/get`, `GET /agent/status`, `POST /agent/update`, `POST /agent/revoke`, `POST /agent/rotate-key`, `POST /agent/reactivate`, `POST /agent/cleanup` | Pending |
| Agent approvals | `POST /agent/request-capability`, `POST /agent/approve-capability`, `POST /agent/grant-capability`, `POST /agent/revoke-capability`, `POST /agent/ciba/authorize`, `GET /agent/ciba/pending`, `POST /agent/device/code` | Pending |
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

The owned fixture reads the original host rows and preserves the legacy public response. Browser revocation updates the host, its eligible agents and their grants in one realm-scoped transaction. An already-revoked host returns zero newly revoked agents. Enrollment preserves the one-hour token deadline, the 15-minute host session lifetime and the host ID on activation. Both writers consume tokens issued by the other. Same-owner key enrollment can merge a pending host into an existing host and retire the pending record. The fixture requires a valid public Ed25519 JWK and refuses unowned or ambiguous key records. The production factory retains its exclusion for projects with agent hosts. Signed machine operations, mixed credentials on the hosted transport and approvals still require compatibility proof before that exclusion changes.

# Project Agent Auth compatibility

The platform installs `@better-auth/agent-auth` 0.6.2. The endpoint inventory below comes from the installed package’s endpoint map and the AllAuth configuration in `lib/features/server.ts`. Paths are relative to the selected project auth base. AllAuth registers the agent device-code handler under a distinct endpoint key so `/agent/device/code` and OAuth `/device/code` continue to dispatch separately.

| Installed surface | Methods and paths | Owned fixture coverage |
| --- | --- | --- |
| Discovery | `GET /agent-configuration` | Public native-format document with the selected auth base, delegated mode, Ed25519, CIBA and device approval, and a one-hour cache. |
| Host listing and detail | `GET /host/list`, `GET /host/get` | Signed browser session |
| Host revocation | `POST /host/revoke` | Fresh verified owner cookie or signed self-revocation by an active owned inline Ed25519 host. |
| Host provisioning and enrollment | `POST /host/create`, `POST /host/enroll` | Fresh verified browser provisioning, inline Ed25519, and one-time enrollment across writers. |
| Host update | `POST /host/update` | Fresh verified browser owner can edit the host and replace its inline key under the existing ID. |
| Signed host key rotation | `POST /host/rotate-key` | Active owned inline host with an exact host-ID issuer and unused JTI. Host-ID changes require a host without linked agents or approvals. |
| Host account switch | `POST /host/switch-account` | Fresh verified browser session of the current owner resets access for a delegated host under its existing ID and key. |
| Delegated registration | `POST /agent/register` | Existing active owned host with a verified inline Ed25519 JWT and one-time JWT ID. Supports active agents, forced device approval and same-owner pending retries that select device or CIBA. |
| Agent identity transfer | `POST /agent/claim` | Pending. |
| Agent session | `GET /agent/session` | Verified active inline delegated agent, live grants, and an explicit public user projection. |
| Agent introspection | `POST /agent/introspect` | Inline delegated agent JWT in the `token` body field, with the native compact public claims and replay checks. |
| Signed agent status | `GET /agent/status` | Known inline Ed25519 host or active delegated agent. Keeps native status and grant fields and the normal active-agent heartbeat. |
| Agent listing and detail | `GET /agent/list`, `GET /agent/get` | Current owner’s signed browser session. |
| Agent profile | `POST /agent/update` | Current agent owner’s signed browser session, with native name and metadata updates. |
| Agent revocation | `POST /agent/revoke` | Signed browser session of the agent or host owner, an active signed host selecting its agent, or an active signed delegated agent disconnecting itself. |
| Agent expiry cleanup | `POST /agent/cleanup` | Live browser owner can expire their overdue active agents and pending approval records. |
| Agent reactivation | `POST /agent/reactivate` | Active signed host and eligible owner, existing delegated inline agent, and empty host defaults for expired-agent renewal. |
| Agent key rotation | `POST /agent/rotate-key` | Active signed inline host can rotate an active owned delegated agent’s inline key. |
| Browser approvals | `GET /agent/ciba/pending`, `POST /agent/approve-capability` | Current owner’s pending device and CIBA summaries. Fresh verified owner can approve or deny an existing, owner-bound delegated registration without capability grants. The decision accepts native `approval_id` or `agent_id`. |
| Agent device code | `POST /agent/device/code`, `GET /agent/status?agent_id=…` | Active signed host can issue or reissue a device code for its pending delegated agent. The host polls the same agent before and after browser approval. |
| Agent CIBA | `POST /agent/ciba/authorize` | Active signed inline host can request poll-only approval for its pending delegated agent and current verified owner, with an empty capability list. |
| Capability grant revocation | `POST /agent/revoke-capability` | Fresh verified browser owner, active signed host, or active signed agent can revoke named existing grants within their scope. |
| Agent capability requests and grants | `POST /agent/request-capability`, `POST /agent/grant-capability` | An active signed agent can submit a request, and a fresh verified browser owner can submit a grant for their agent or their host’s agent. The configured empty catalog rejects both without creating approvals or grants. |
| Capability catalog | `GET /capability/list`, `GET /capability/describe` | A live signed host or agent can read the configured empty catalog. |
| Capability actions | `POST /capability/execute`, `POST /capability/batch-execute` | An active signed agent receives the native unknown-capability error for each action. |

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

The account-switch route follows the platform’s current-owner check. It retires linked delegated agent keys and grants in one transaction and returns the native count and identical previous and new owner IDs. Claimed, rejected, and revoked agents keep their stored state. Native reads after rollback recognize the revoked agents and accept the original host key. Hosts with autonomous agent records stay outside the fixture scope.

The native pending list accepts a current browser session and scopes rows by owner. The decision endpoint confirms a fresh verified browser session and matches the approval, delegated agent and existing active host to that owner. Device approval checks the existing hashed code. When both device and CIBA requests are live, the decision requires an explicit approval ID and applies that request’s proof rules. Decisions resolve compatible pending rows and the agent status in one transaction. Unowned hosts, host transfers, capability grants and push delivery remain outside the fixture scope.

Signed status accepts a host ID or unique key ID and scopes the requested agent to that host. Agent credentials resolve their own subject, validate the configured audience and any native request binding, and consume the JWT ID once in the selected realm. An eligible owned delegated agent with an empty host budget can renew its 15-minute session after idle or activation expiry. The renewal clears previous grants and respects the 24-hour absolute lifetime. Host polling stays repeatable. Hosted browser management uses a session cookie. Both writers reject the same Agent bearer credential on verified hosted routes. The SDK browser proxy does not forward Agent endpoints.

Delegated registration binds the new agent to the same owner and host, retains its inline public key and native 15-minute lifetime, and updates the host heartbeat on success. The fixture serializes the five-active-agent limit across an owner’s hosts and consumes registration JWT IDs separately from repeatable host status reads. Forced registration and compatible retries produce a pending agent and a device approval tied to the verified host owner. The stored agent owner keeps the same browser authority after a rollback to native.

The signed host can issue a new device code for its pending delegated agent. The response retains the native grouped user code, five-minute expiry, five-second poll interval, and `/device/capabilities` URL. The integration supplies that approval page. AllAuth’s `/device` handles OAuth device authorization separately. Browser approval uses the existing agent endpoint, and the host polls its agent at `/agent/status`.

Native forced registration can leave the agent and its device approval unbound. The candidate accepts the live device code only from the fresh, verified owner of its active host and binds the agent during that decision. Signed reissue by the verified host binds pending records before a new proof is returned. For existing unbound rows on the native writer, its original approval policy still applies.

Direct CIBA issuance accepts a pending agent on the verified signed host and its current owner’s login hint. The stored poll-only approval has a five-minute deadline and a five-second interval. Other login hints receive the native opaque response without a stored approval. A request without an agent can create an owner-bound receipt for the browser’s pending list. Both writers require an agent for an approval decision. New owned CIBA issuance binds the pending agent and compatible records before returning the proof, preserving owner checks on native rollback. Isolated PostgreSQL tests verified both issuer-to-decision directions and signed host polling. Push delivery and nonempty capability scopes remain outside this scope.

A signed registration retry for the same pending agent and host can select CIBA. It returns the saved agent identity and native approval summary. The browser obtains the approval ID from `/agent/ciba/pending`. The stored approval uses the current verified owner and retains the native binding message, poll interval and deadline. A new forced registration starts with a device code. Isolated PostgreSQL tests verified retry approval in both writer directions, transaction rollback and durable replay rejection.

Browser agent list and detail accept the current owner’s signed session and expose the native grant projections. List preserves status, mode, and host filters and pagination. Browser revocation locks the live session and target authority, clears the agent’s inline signing key and key ID, and revokes its grants in one realm-scoped transaction. The persisted host owner can revoke an agent on that host even when the agent is unbound. The installed client’s disconnect operation uses an active signed host and an explicit agent ID. This operation remains repeatable under the same valid host proof and leaves the host and other agents usable. Legacy reads after rollback recognize the updated rows.

A signed delegated agent can disconnect itself with its own active credential. The target defaults to the verified agent when the request omits `agent_id`. The fixture checks the realm audience, any request binding and the single-use JWT ID before retiring the key and revoking grants in the same transaction. The native browser route reads the resulting revoked agent and grants after rollback.

Browser profile updates require the agent owner’s live session. The native metadata map accepts string, number, boolean and null values. A supplied map replaces the stored map, and a request containing only the name retains the previous metadata. The write changes the profile and update time under the same agent ID.

Browser cleanup changes due active agents and due pending approvals for the signed owner to `expired`, using one transaction and the existing five-per-minute limit. The native response counts each transition. Expired agent rows retain their signing keys and grants for the separate reactivation flow.

Explicit reactivation verifies the same host’s existing signed key and locks its eligible owner and delegated agent. With empty host defaults, it clears old grant rows and starts a new 15-minute agent session under the existing ID and key. A repeat on an active agent reads the existing session. The absolute lifetime retires an expired agent’s key and grants. Reactivation with configured capabilities or approval requirements still needs separate coverage.

Capability revocation accepts the fresh verified browser owner of the agent or its persisted host, a live signed host selecting one of its agents, or a live agent selecting itself. It changes every matching existing grant and returns the changed capability names and grant IDs. Agent credentials require the native audience and single-use JTI and validate any supplied method, URL and JSON body binding. An authorized retry with a fresh agent credential returns empty change lists.

Signed host self-revocation verifies the active host’s existing inline key, accepts its exact ID or an unambiguous key ID as the issuer, and applies the same grant cascade as browser revocation. Successful revocation clears the verifying key. A retry using that key receives the native authentication error, including after rollback. The fixture covers direct requests to the selected realm.

Browser host update replaces the inline Ed25519 key under the original host ID and preserves existing agent and approval links. The candidate rejects a key ID already assigned to another host or matching another host ID. The native and owned engines accept each other’s replacement keys and reject the previous key after a successful write.

Signed host rotation uses the replacement JWK thumbprint as the host ID. The installed route’s issuer lookup requires the existing host ID. A client using the key ID as its issuer can rotate through this route when those IDs match. PostgreSQL’s agent and approval foreign keys prevent changing the ID of a referenced host. The fixture reports that conflict before writing and supports same-ID key metadata updates under the same authorization.

The installed delegated-agent rotation endpoint requires a host JWT. The fixture replaces the inline key and key ID under the same agent, host and owner, with the native five-per-minute limit. A previously accepted host proof can retry the current replacement key for that agent. Another key change for the same agent requires a fresh proof. The client from the matching upstream release tag sends an agent JWT for this endpoint. The tested compatibility lane is the native host-signed HTTP request. [Tagged Agent Auth client](https://github.com/better-auth/agent-auth/blob/a6736a4414e6cd3febffc86d00d9924694883364/packages/sdk/src/client.ts#L1005)

Capability catalog reads preserve the native empty list and unknown-capability response. Both require a live signed host or delegated agent in the selected realm. Agent credentials share the same single-use proof records and bounded heartbeat as signed status. Host credentials remain reusable for catalog reads within their existing lifetime.

The discovery document uses the validated auth base of the selected realm for each advertised endpoint. Capability request and execution validate the signed agent credential and any method, URL and body binding. Grant requests require a fresh verified browser session and ownership of the target agent or its host. PostgreSQL fixtures compare native response bodies and authentication challenges and verify that the candidate leaves approvals, grants and host budgets intact. Signed denials still consume the proof and renew the bounded heartbeat. Stored grants and host budgets cannot supply a capability definition or cause execution.

Introspection validates the body token against the active agent’s stored inline key and returns the native identity, stored expiry and currently active grants. It preserves legacy body tokens with optional audience and JTI claims. A supplied audience must match a native audience for the selected realm, and a supplied JTI shares the persisted replay check with status and catalog reads. The fixture accepts a single credential in the request body.

The installed session endpoint returns its adapter user object inside the Agent Auth session. The owned fixture selects AllAuth’s public project-user fields for the verified agent’s active owner. The projection excludes private metadata, directory management fields and moderation details. The endpoint retains the native public agent, host and grant shape, including JWT grant filtering, and renews the bounded agent heartbeat. A browser cookie or valid host proof alone returns the native empty session.

## Protected project rollout

The normal factory checks stored Agent state for the protected development project selected by immutable ID. Agent admission requires a matching `ALLAUTH_PROJECT_ENGINE_AGENT_BRIDGE_ID` and signed operator evidence for the exact legacy writer revision. The supported state includes realm-owned inline Ed25519 hosts with empty budgets, delegated agents and owner-bound device or poll-only approvals, including compatible older pending device rows. The factory rejects remote keys, ambiguous identifiers, unowned hosts, autonomous state, stored grants and incompatible approval authority. The writer command repeats the same stored-state check under its exclusive admission lock before switching. The existing database writer lease fences Agent tables and replay rows through both writer directions. The selected bridge’s native Agent key rotation uses the same transactional replay check as AllAuth. An identical retry can confirm the stored key, while the same proof cannot install a different key.

1. Deploy a bridge-capable release while the protected project remains on the legacy writer. Set `ALLAUTH_PROJECT_ENGINE_AGENT_BRIDGE_ID` to its exact immutable ID and leave `ALLAUTH_PROJECT_ENGINE_INTERNAL_ID` unset for this project until there is drain evidence. An empty bridge setting preserves native Agent behavior, as does a bridge setting for a sibling project. Verify in the deployment controller that the bridge deployment is serving and that every previous memory-only process has stopped serving this project. Record the bridge deployment reference and the time the last old process stopped serving. The isolated test cannot establish either production fact.
2. Keep the legacy writer for at least 90 seconds after the observed drain. The installed native verifier accepts proofs up to 60 seconds old and PostgreSQL retains consumed proofs for 90 seconds. Historical in-memory JTIs cannot be recovered. Use the same bridge ID in the trusted operator environment connected to the same database and platform signing secret, then issue the evidence.

   ```sh
   node scripts/project-engine-writer.mjs agent-replay-evidence "$BRIDGE_DEPLOYMENT" "$LAST_UNBRIDGED_REQUEST_AT_UTC"
   ```

3. Keep the bridge ID and set `ALLAUTH_PROJECT_ENGINE_INTERNAL_ID` to the same project on the candidate deployment and in the trusted writer command environment. Set the returned JSON as `ALLAUTH_PROJECT_ENGINE_AGENT_REPLAY_APPROVAL`. Set `ALLAUTH_PROJECT_ENGINE_INTERNAL_PREPARE_REVISION` to the current legacy revision and verify normal readiness before using `switch legacy <revision> allauth`. Preparation and the switch require evidence issued less than 15 minutes earlier. The command checks the evidence under the writer admission lock. Reconfirm that the deployment has had no memory-only process since the recorded drain. An already active writer keeps serving its exact approved revision after the preparation window. Keep the matching bridge ID on the bridge-capable rollback deployment and in the rollback command environment. A later activation requires fresh evidence for the new legacy revision, and any rollback to a release before bridge support requires a new observed drain and waiting period.

## Production project rollout

Register the exact project and workspace IDs while the production project is still on the legacy writer. Add the immutable project ID to `ALLAUTH_PROJECT_ENGINE_PRODUCTION_AGENT_BRIDGE_IDS` on each rollout-capable replica and in the operator environment. This setting accepts comma-separated canonical lowercase project UUIDs. The bridge starts on the enrolled legacy realm before its entry is added to `ALLAUTH_PROJECT_ENGINE_PRODUCTION_REVISIONS`. Readiness verifies the configured bridge projects against the production registry. The supported Agent state and PostgreSQL replay records are the same as for the protected project.

Verify that the bridge deployment is serving and record when the last memory-only replica stopped serving that realm. After at least 90 seconds on the legacy writer, issue evidence from the release container against the same database and platform signing secret. Use a UTC timestamp ending in `Z` for the observed drain time.

```sh
node scripts/project-engine-writer.mjs --project "$PROJECT_ID" agent-replay-evidence \
  "$BRIDGE_DEPLOYMENT" "$LAST_UNBRIDGED_REQUEST_AT_UTC"
```

Set `ALLAUTH_PROJECT_ENGINE_PRODUCTION_AGENT_REPLAY_APPROVALS` on the candidate deployment and in the writer command environment to a JSON object keyed by immutable project ID. Each value is the signed JSON object returned by the command for that project. Add the exact legacy revision to `ALLAUTH_PROJECT_ENGINE_PRODUCTION_REVISIONS` and verify readiness. Activation requires a receipt issued less than 15 minutes earlier and rechecks stored Agent state under the writer admission lock. A later activation requires fresh evidence for its new legacy revision.

Keep the exact bridge ID configured on the rollback deployment and in the rollback command environment while the realm has stored Agent state or unexpired replay rows. The rollback can proceed after the original receipt’s preparation window expires. The legacy writer reads the same replay records and preserves proof consumption after a restart.

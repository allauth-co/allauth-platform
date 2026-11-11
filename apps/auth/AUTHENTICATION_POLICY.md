# Authentication policy and log explorer

Console configuration is scoped to the platform or one application environment. `GET /api/admin/configuration?project=<slug>` reads the selected environment; omit `project` for the platform. `PATCH` uses the same URL, a fresh verified platform-administrator cookie, the exact platform `Origin`, and a complete versioned document:

```json
{
  "version": 0,
  "policy": {
    "emailAndPasswordEnabled": true,
    "signUpEnabled": true,
    "requireEmailVerification": true,
    "sessionExpiresInSeconds": 604800,
    "mfaMode": "optional",
    "organizationCreation": "verified-users",
    "passwordPolicy": {
      "minLength": 8,
      "maxLength": 128,
      "requireUppercase": false,
      "requireLowercase": false,
      "requireNumber": false,
      "requireSymbol": false
    }
  }
}
```

Only these settings are accepted. `passwordPolicy` defaults to the values shown for stored policies that predate this field. Session expiry is 900–2,592,000 seconds. Organization creation accepts `verified-users`, `admins-only`, or `disabled`. Social-provider and email availability is returned from the actual environment configuration; the API does not create provider credentials or enable SMS. Keep at least one configured sign-in method available. Platform changes also require a viable method linked to the current administrator.

Save the current returned `version`. Concurrent/stale saves return `409`; reload before retrying. The new version and its `configuration.updated` event commit in one PostgreSQL statement. The next request loads the stored version and rebuilds the native Better Auth instance without restarting the service. Platform instances share one bounded pool; environment instances use a bounded cache that retains active requests safely. New and refreshed sessions use the configured expiry; existing sessions are not shortened retroactively.

`requireEmailVerification` controls native sign-in. Account security/session controls, administrative authority and organization creation still require a verified account. Closing sign-up also blocks social provisioning and guest sessions; authorized administrator and SCIM provisioning remain available. Disabling passwords blocks email/username password login and password reset/change endpoints.

Magic links and email sign-in codes follow `signUpEnabled` too. When registration
is open, completing a valid link or code can create a new, email-verified account
and session. Requesting an email alone does not create an account. When
registration is closed, existing users can still sign in with either method;
neither method can create a new account. Links and codes expire after five
minutes and cannot be reused after successful verification. Invalid or expired
hosted magic links open `/auth-error` with a route back to sign-in.

The hosted `/api/config` response advertises the effective instance policy as
`emailPassword`, `signUpEnabled`, and `emailVerificationRequired`. Custom-domain
pages use their bound application environment and its mail transport; a query
parameter cannot select another application's policy. Hosted forms hide disabled
password login and registration controls. A direct visit to a closed sign-up page
offers a sign-in link. Successful registration without email verification or an
immediate session returns to sign-in, preserving the authentication continuation.
The downloadable React SDK uses the same optional capability names.

Required MFA is deliberately conservative: close public sign-up, require email verification and enroll every active account before saving `mfaMode: "required"`. Unenrolled or unverified accounts cannot create/use ordinary sessions under that policy, and users cannot disable MFA. Native enrolled authentication still completes the TOTP/recovery challenge. Administrators can use the existing audited impersonation flow; impersonation cannot change the target's credentials or factors.

## First-time console setup

A verified platform user without workspace membership or prior workspace
participation receives one default workspace on their first interactive Console
visit. The console makes an explicit same-origin `POST /api/workspaces/onboarding`
after loading memberships and invitations. Pending invitees continue to their
invitation instead; existing members, administrators, impersonation, and invalid
accounts are excluded. Tenant authentication and broker sessions alone never
start console setup. New workspace and owner membership creation is atomic and
idempotent under concurrent requests. Durable audit history prevents automatic
recreation after deliberate workspace deletion or departure.

The default name comes from the current saved profile, or falls back to “My
workspace”. Workspace names are independent from profile names after creation.
Users may add a display name without choosing a username. Supplied usernames
retain native format and uniqueness validation. Profile updates invalidate the
platform team and user views so the current name appears immediately.

Additional workspaces can be created with `{ name, slug? }`; missing slugs are
allocated from the name. Slug availability is advisory and the database enforces
uniqueness on creation. Duplicate custom slugs return a readable conflict while
the form preserves its values. Display names can repeat; identifiers cannot.

## Password rules

Choose an application and its Development or Production environment, then open **User & authentication → Email & password → Password rules**. Each environment saves its own policy. The default minimum is **8 characters**; the maximum is **128**. Minimum length accepts whole numbers from 6 to 128, maximum length from 8 to 128, and the maximum must be at least the minimum. Uppercase, lowercase, number and symbol requirements are optional and off by default. Uppercase/lowercase checks use A–Z/a–z, number uses 0–9, and a symbol is a character that is neither a Unicode letter/number nor whitespace.

The native runtime enforces the selected rules when creating or replacing passwords, including signup, recovery, password changes, password setup and managed account creation/reset. Changing rules does not invalidate stored passwords: existing users can still sign in with their current password. Their next replacement must satisfy the current policy.

Both hosted `/api/config` and same-origin `/api/allauth/sdk/config` advertise `passwordPolicy`. Hosted forms and the React SDK use the effective rules for new-password fields and show requirements before submission. SDK servers that omit the field use an 8–128 character client fallback; server validation remains authoritative. Existing SDK installations must update to the matching SDK source/archive to consume the new settings.

Versioned configuration updates should include the complete `passwordPolicy` returned by the read. Do not omit it when changing another setting after customization: omission is backwards compatible and resolves to defaults. Saved policy documents without this field also adopt the new default on their next read.

## Native log explorer

`GET /api/auth/control/logs` accepts `scope=user|organization|admin`, the existing `userId`, `organizationId`, `type`, `outcome`, `from`, `to`, `q`, `limit` and `offset` filters, plus exact `ipAddress`, `actorId`, `targetId`, `clientId`, and `sessionId` filters. IP addresses must be literal canonical IPv4/IPv6 addresses. Search is parameterized and treats wildcard characters literally. `sessionId` matches safe event metadata or native session/sign-in target IDs; it never accepts or returns a session token.

`GET /api/auth/control/logs/detail?id=<event-id>` accepts the same scope/filter fields. A detail lookup enforces the same fresh account, organization membership or administrator authority as the list and the same configured retention window. A guessed foreign or expired ID returns `404` in an otherwise authorized scope.

Lists return `{events,total,limit,offset,retentionDays}`; detail returns `{event}`. Events are projected through the existing metadata whitelist: no response bodies, passwords, OAuth credentials, session tokens, private user metadata or arbitrary nested objects. PostgreSQL supports all filters. The adapter-only fallback supports exact column filters and explicitly rejects text/session searches rather than returning incomplete results. Every response is marked `no-store`.

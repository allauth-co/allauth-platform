# AllAuth MCP

Manage the hosted AllAuth service from Codex, Claude Code, Claude Desktop, and other local stdio MCP clients. This package uses the existing management HTTP APIs with an authorized AllAuth root-account session. It does not require browser automation for supported operations.

See [INSTALL.md](./INSTALL.md) for build, Google/device login, optional password login, client configuration, skill installation, and local archive distribution. Node.js 22.14 or newer and pnpm are required. The package is not published to a registry.

## Coverage

The catalog defines **88 tools**: **79 are available by default**, **30 in read-only mode**, and all 88 when sensitive tools are enabled with writes permitted. Availability is a local connection policy; every call still passes the service's authorization and tenant checks.

| Operation family | Supported controls |
| --- | --- |
| Workspaces | List, create, rename, delete empty workspaces; inspect members and invitations; change member roles; remove members; send, resend, cancel, and accept invitations. |
| Application environments | List authorized environments; provision Development or Production in an explicit workspace; rotate proxy credentials. Provisioning and rotation require sensitive tools. |
| Domains | List and add custom authentication domains; obtain DNS requirements; check verification; remove domains. DNS-provider changes remain outside these tools. |
| Users | Search, inspect, create, ban/unban, change roles, replace supplied metadata, revoke sessions, and delete users in one exact application environment. |
| Organizations | Search and inspect organizations; page and search all members, team rosters, teams, roles and invitations; create, update, delete; manage membership and access. Existing ownership and directory-management rules apply. |
| Authentication and branding | Read and update versioned authentication policy; read and update complete application branding; upload inline image assets. Branding is shared by the application's environments. |
| Activity and sessions | Read overview counts, UTC analytics and cohorts, retained events and detailed logs; list safe session attributes and revoke a session by ID. |
| Abuse protection | Read and update the environment policy; add and remove IP/email-domain rules. |
| Webhooks | List endpoints and delivery metadata; create/delete endpoints; rotate signing secrets; requeue eligible failed deliveries. Secret-returning actions require sensitive tools. |
| OAuth clients | Read environment-native clients; platform administrators can list/create/update/delete root-platform integration clients. Creation requires sensitive tools. |
| Managed SCIM | List and create connections bound to an existing verified organization SSO provider; rotate/revoke credentials; decommission connections. Credential-returning actions require sensitive tools. |

Exact input schemas and the enabled tool list are available through `allauth://capabilities`. Read `allauth://guide` for operating guidance. The `allauth_setup` prompt starts application setup; `allauth_investigate_user` starts an investigation with read operations.

`allauth_organization_get` returns a bounded summary, not a complete directory.
Use `allauth_organization_members_list`, `allauth_organization_teams_list`,
`allauth_organization_roles_list` and `allauth_organization_invitations_list`
with `search`, `limit` (1–100) and `offset`. Follow each response's `total`,
`limit` and `offset` until the requested records are covered. Members accept
`teamId` to read a team roster and `excludeTeam: true` to find organization
members available to add to that team. `allauth_users_list` accepts
`excludeOrganizationId` to find users outside an organization's membership.
These reads require the accompanying service routes to be deployed; the local
MCP build alone does not add them to a deployed server.

## Authentication and boundaries

`login` defaults to device authorization: the terminal prints an approval URL and user code, and the user completes one browser approval using their Google-connected AllAuth account. The CLI does not open the browser or ask for a Google password. It polls until approval, denial, expiry, or an error. If AllAuth requires MFA, the terminal then prompts for a hidden TOTP or one-use recovery code, even when browser MFA was completed. Keep codes in that local prompt. The CLI verifies workspace access before saving the signed management cookie. Subsequent MCP operations run without the browser until the session expires.

Failed or cancelled terminal MFA requires a new `login` and browser approval. The device grant has already been consumed; the CLI cannot redeem it again and does not save the partial challenge as a management session.

Device login requires the matching app-local server integration that returns a signed native session cookie to this first-party MCP flow. Its deployment and live sign-in must be verified separately from the package build. A device access token is never used as a management cookie or bearer token, and a missing session cookie prevents persistence.

`login --method password` retains terminal-only email/password login with TOTP or one-use recovery codes. It requires an existing AllAuth password credential; a Google password cannot authenticate a Google-only AllAuth account this way. The CLI does not automate SSO provider login, passkeys, or email-only MFA in the terminal, or change the account's enabled methods. Existing authorized cookie sessions remain an alternative private credential source.

Both methods save sessions in a private, origin-specific local store. `doctor` checks the configured session. `logout` forgets the saved local session; it does not revoke it remotely. When invoking a source-package script use `pnpm run login`; `pnpm login` is the separate package-registry command.

The server cannot administer root-platform users, impersonate users, reset arbitrary passwords, or write tenant-native OAuth clients through workspace authority. SSO provider mutations require a separate tenant-session workflow and are not exposed here. It does not install or configure an identity provider, change provider secrets or infrastructure environment variables, edit DNS at the provider, deploy AllAuth, or migrate application users. Managed SCIM setup uses an already verified SSO provider.

This package exposes **stdio only**. It does not host an HTTP/SSE MCP endpoint, OAuth authorization server, public connector, or Claude Desktop extension bundle. AllAuth's service origin is an ordinary HTTP API origin and is not a remote MCP endpoint. Better Auth's separate `@better-auth/mcp` authentication plugin does not install this management server.

## Connection controls

- `ALLAUTH_URL`: exact service origin, defaulting to `https://allauth.co`; HTTPS is required except for loopback development.
- `ALLAUTH_READ_ONLY=true`: hides write tools and independently rejects a non-GET operation at the server boundary.
- `ALLAUTH_ALLOW_SENSITIVE=true`: enables tools that can return integration credentials. Disabled by default.
- `ALLAUTH_COOKIE`, `ALLAUTH_COOKIE_FILE`, `ALLAUTH_CREDENTIALS_FILE`: private credential sources described in [INSTALL.md](./INSTALL.md).

Discovery works before login. Tools have strict schemas and fixed API routes; callers cannot choose arbitrary URLs, headers, or methods. The HTTP client sends the configured origin, refuses redirects, bounds response size and time, and avoids returning response bodies in errors. Directory and audit tools support bounded pages and filters.

Mutation outcomes can be uncertain after a timeout. Read the resource before retrying. Invitations and webhook retries can contact other systems or people; perform them only when the user's task authorizes that action. Provider acceptance, queued delivery, and domain registration are separate from confirmed delivery or verification.

## Develop and package

```sh
pnpm install --frozen-lockfile
pnpm typecheck
pnpm exec vitest run src/catalog.test.ts src/client.test.ts src/server.test.ts
pnpm build
pnpm pack --pack-destination /absolute/path/package-output
```

Run these commands from `apps/auth/mcp/`. Tests use local fixtures or injected HTTP boundaries; live production mutation is not required. The archive includes the built CLI/server, the portable `skills/allauth/` skill, and installation guidance. Installing the skill alone does not connect the server or grant access.

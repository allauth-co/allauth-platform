# Client workspaces

Any active account with a verified email can create a console workspace. Sign in to the AllAuth platform and open **Workspaces**. These ownership records are separate from the end-user organizations stored inside each application's authentication database.

A workspace owner or administrator manages its applications and each application's users, organizations, authentication settings, audit logs and security controls. A member sees a workspace summary. Membership never changes that person's platform administrator role or their role inside an application's end-user database. Removing or demoting a workspace administrator removes their console access on the next request.

Platform administrators retain global access. Existing applications belong to a protected **AllAuth platform** workspace; legacy creators do not automatically receive client ownership.

## Applications and environments

Every application belongs to a workspace. Select the workspace before creating an application, then provide its workspace ID, name, unique environment slug and exact app origin. Development allows loopback HTTP; production requires HTTPS. Add the other environment with the same `applicationId` and workspace ID. Each application can have one Development and one Production environment. Development and production keep separate PostgreSQL schemas, users, organizations, credentials, sessions, audit logs and security settings. An application group cannot span workspaces.

The one-time proxy secret returned after creation belongs on the app server. Workspace owners and administrators can rotate it through the existing project proxy-secret route. The server records the rotation and registry update in one transaction.

## Limits

Default self-service limits are three owned workspaces per account, five application groups per workspace, two environments per application, 50 members per workspace and 20 pending invitations. Platform administrators are exempt from self-service quotas. APIs return the effective `limits` alongside workspace and project lists.

Configure `WORKSPACE_MAX_OWNED`, `WORKSPACE_MAX_APPLICATIONS`, `WORKSPACE_MAX_MEMBERS` and `WORKSPACE_MAX_INVITATIONS` on the AllAuth server. Invalid or excessively large settings fall back to the published defaults. Ownership and application limits are checked while holding database locks, including concurrent requests.

## Membership

Invite an account by email with role `member`, `admin` or `owner`. Invitations last seven days and appear only to the signed-in account whose current verified stored email matches the invitation. Acceptance is a same-origin operation; it cannot use a submitted email, an impersonated session or a tenant-only cookie. Expired, cancelled, replayed or no-longer-authorized invitations are refused.

Owners can assign and remove owners. Administrators manage ordinary members and administrators. Every client workspace must retain an owner. Transfer sole ownership before deleting the platform account; a database constraint also prevents an account deletion or concurrent member removal from orphaning the workspace. Empty workspaces can be deleted by an owner or platform administrator.

## API

All endpoints require the platform's fresh native session cookie. Mutations require the exact AllAuth platform `Origin` and bounded JSON bodies. Responses use `Cache-Control: no-store`.

| Route | Operation |
| --- | --- |
| `GET /api/workspaces` | Accessible workspace summaries and limits |
| `POST /api/workspaces` | Create `{name, slug}` and the caller's owner membership |
| `GET /api/workspaces/:id` | Summary, management permissions, and permitted member/invitation lists |
| `PATCH /api/workspaces/:id` | Rename with `{name}` |
| `DELETE /api/workspaces/:id` | Delete an empty client workspace |
| `PATCH /api/workspaces/:id/members/:memberId` | Set `{role}` |
| `DELETE /api/workspaces/:id/members/:memberId` | Remove a member while retaining an owner |
| `POST /api/workspaces/:id/invitations` | Create `{email, role}` |
| `DELETE /api/workspaces/:id/invitations/:invitationId` | Cancel an invitation |
| `GET /api/workspace-invitations` | The caller's pending email-bound invitations |
| `POST /api/workspace-invitations/:invitationId/accept` | Accept using current verified identity |
| `GET /api/admin/projects?workspace=:id` | Managed applications and environments |
| `POST /api/admin/projects` | Existing project payload plus `workspaceId`; `applicationId` adds its other environment |

Every caller, including a global administrator, must explicitly select an authorized workspace when creating an application. Missing workspace input is rejected before creating an application or its identity broker. Legacy applications remain in the protected AllAuth platform workspace; creation never chooses that workspace implicitly.

Native OAuth client registration remains restricted. A private server helper creates only a fixed project identity broker after validating workspace authority, using the caller's genuine native platform session. Its temporary permission cannot be activated through headers or JSON and does not grant generic client registration or resource management. Callback updates are limited to the project's app proxy, server-owned hosted origins and fully active, verified custom-domain pairs. Pending or deleting custom domains do not gain callback authority.

Migration `009-workspaces.sql` runs only in the platform schema. No end-user organization tables are reused for client-console ownership.

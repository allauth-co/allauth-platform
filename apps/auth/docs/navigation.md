# Console and account navigation

AllAuth has one Console entry, `/admin/workspaces`. A direct sign-in on the
AllAuth domain opens it for a verified, admitted platform account. The `/console`
entry resolves the current authenticated realm on the server; customer account
domains continue to open `/account`. Unverified, anonymous, banned and
impersonated sessions stay in account management. Console endpoints continue
to enforce current session and workspace permissions independently of navigation.

Explicit account, invitation and device callbacks retain their existing
destinations. Signed OAuth requests continue through the authorization server,
and MFA completes before navigation. `/dashboard` uses the same Console entry.
The public homepage remains available independently of the authenticated entry.

The Console has a compact context bar and one primary navigation row when the
current view has sections. The bar
shows the selected Workspace, Application and Environment. Context controls
change that selection; the primary row follows the most specific available
context:

- Application: Overview, Users, Organizations, Logs and Configure.
- Workspace: Applications, Team and Workspace settings. Members see Workspace
  summary instead of management links.
- Platform administration: Overview, Users, Organizations, Logs and Configure.
- Global: the Workspaces grid needs no additional navigation row.

The workspace context dropdown keeps parent actions available while an
application is selected: Applications, Team and Workspace settings. Workspaces
is accessible through the AllAuth logo and workspace dropdown. Platform
administration appears in a distinct dropdown footer for platform
administrators; it is not an alternative workspace selection or an extra
stacked navigation row. Invalid or unavailable scope never enables application
management navigation.

Application selection preserves the workspace scope.
Switching applications opens Overview; switching environments within an
application retains the current section and clears filters tied to old records.
The styled Application menu includes New application for workspace owners and
admins, with the current workspace fixed in the creation panel. The Environment
menu offers the missing Development or Production instance, with both workspace
and application fixed. Opening either panel does not create anything; successful
creation opens the new instance and displays its integration key once.
An application always belongs to a workspace. Without a valid selected workspace,
the applications view asks the user to choose one and does not list a global
application gallery. Filters and form selectors use the same styled pulldowns,
including keyboard selection and empty All options.

The same account avatar and menu appear in Console, account management and
hosted account pages. The menu contains the signed-in identity, Manage account,
Account security, eligible Console access and Sign out. Hosted portals omit
Console access. Account settings can retain an explicit validated Console return
destination; only UI routes, workspace/application scope and the workspace
Team or Workspace settings tab belong in that
destination, and the destination grants no authority.

Workspace membership, platform accounts and application end-user organizations
remain separate concepts. The workspace picker selects who manages an
application. An organization's membership and account security remain under the
account and organization views.

Starting application-user impersonation keeps the selected workspace, environment
and user open. A support banner remains visible across that environment's console
pages, with the current target, expiry and End support session action. Its state
comes from the live native session, not a URL flag. The console account remains
the administrator's real platform account. The status check cannot refresh the
support session lifetime; ending an already-expired session safely clears the UI
after confirming that no live impersonation remains.

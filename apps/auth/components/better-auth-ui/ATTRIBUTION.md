# Better Auth UI integration

These components adapt the official [Better Auth UI](https://better-auth-ui.com) shadcn registry for the installed `@better-auth-ui/core` and `@better-auth-ui/react` version **1.7.27**. Upstream copyright and the complete MIT license are retained in [LICENSE](./LICENSE).

The relevant components and their dependencies were retrieved directly from `https://better-auth-ui.com/r/radix-nova/<name>.json`: `auth`, `auth-provider`, `settings`, `user-button`, `organization`, `two-factor`, `username`, `magic-link`, `email-otp`, `passkey`, `last-login-method`, `delete-user`, and the email-first view from `sso`. Imports are namespaced here; existing application primitives and logos were preserved.

Missing primitives in `ui/` adapt the official [shadcn/ui](https://ui.shadcn.com) MIT registry at `https://ui.shadcn.com/r/styles/new-york-v4/<name>.json`: `field`, `input-group`, `item`, `empty`, `spinner`, `combobox`, `button`, `alert-dialog`, `checkbox`, `slider`, `tabs`, `input-otp`, and `switch`. The shadcn copyright and complete MIT license are retained in [ui/LICENSE](./ui/LICENSE). The concrete-icon registry avoids website-only placeholder components. `item` uses the already installed Radix Slot package.

AllAuth-specific adaptations:

- The provider reads enabled social/email providers from the server configuration. No payment, infrastructure dashboard, popup, or unconfigured provider is activated.
- The navigation adapter validates local destinations and preserves signed OAuth authorization parameters across authentication views. Native MFA pending responses never trigger a successful-session redirect.
- Password, username, email-code, passkey, and optional popup response handlers share the same MFA-aware continuation. The configured social flow uses redirects.
- Account session management uses an opaque-ID projection and ownership-checked revoke endpoint. The upstream token-based session and multi-session controls are not enabled.
- Profile avatars and organization logo uploads are disabled because upload storage is not configured. Native profile, password, passkey, MFA, organization, invitation, team, and role operations retain the server's authorization checks.

The source and library versions above describe this local implementation; production release and browser verification are tracked by the repository release runbook.

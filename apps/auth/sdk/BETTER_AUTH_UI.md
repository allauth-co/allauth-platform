# Better Auth UI in an embedding application

The platform console uses the official [Better Auth UI shadcn registry](https://better-auth-ui.com/docs/shadcn/integrations/nextjs), with its MIT attribution retained in `components/better-auth-ui`. The portable SDK provides an optional `@allauth/react/ui` provider for consumers that install their own official registry components. It contains no Next.js import, application path alias, server credential, or dependency on the console's component directory.

For the shared widgets with managed application branding, use the default
`AllAuthProvider`, `SignIn` and `SignUp` from SDK **1.4.2** as shown in
[INTEGRATION.md](../INTEGRATION.md). That provider automatically loads the public
application settings through the same-origin SDK configuration endpoint.
**Configure → Application → Settings** controls the name, light/dark logos,
favicon, support email, accent colors and attribution for both Development and
Production. The favicon is exposed through `useAllAuth().publicBranding`; the
SDK does not alter the host application's document head.

The optional registry provider below supplies authentication and query-cache
integration. It does not automatically apply the portable widgets' managed
presentation to consumer-owned registry components. Those components retain
their own appearance configuration.

Use React **19.2.6 or newer** and Tailwind **4.3.2 or newer** for the current official registry. Install `@better-auth-ui/core` and `@better-auth-ui/react` **1.7.27** plus `@tanstack/react-query` **5.104.1**, and add only the official registry views and their UI dependencies that your app uses. Keep the registry's MIT license. Follow its Next.js integration instructions without overwriting unrelated application primitives.

```tsx
"use client";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { AllAuthUIProvider } from "@allauth/react/ui";
import { Auth } from "./components/auth/auth";

export function SignInPage() {
  const router = useRouter();
  return (
    <AllAuthUIProvider
      basePath="/api/allauth"
      projectKey="your-server-configured-project"
      twoFactorPath="/auth/two-factor"
      basePaths={{ auth: "/auth", settings: "/account" }}
      redirectTo="/account"
      Link={Link}
      navigate={({ to, replace }) => replace ? router.replace(to) : router.push(to)}
    >
      <Auth view="signIn" />
    </AllAuthUIProvider>
  );
}
```

`projectKey` isolates and replaces the UI query cache when a consumer changes projects. The same-origin server proxy determines the project; this browser value never changes the authorized server binding. Configure the proxy using the SDK's server-only `next` entry, with its project slug and proxy key kept server-side. Native cookies carry authentication; no browser bearer token or client secret is required.

Omit `socialProviders` to load Google, Apple and Microsoft automatically from the validated same-origin `/api/allauth/sdk/config` response. The wrapper selects Google's advertised direct or broker provider and labels the broker as Google. An explicit provider array overrides discovery; `[]` deliberately hides all social providers. Keep provider credentials on the AllAuth server.

Only enable UI plugins supported by the installed native client and the `/api/allauth/sdk/config` response. The SDK client supports organization/team, passkey, and two-factor actions. Use the matching official UI plugin wrappers if needed. Do not configure a direct Google client secret, popup flow, admin plugin, payment provider, or platform-only capability in an embedded app.

Map `twoFactorPath` to a page rendering `<Auth view="twoFactor" />` under the same provider and register the matching official `twoFactorPlugin({ allowPasswordless: true })` UI wrapper. The example above is only the primary sign-in page. The provider sends native MFA requests to that explicit challenge route and blocks stock passkey/autofill success navigation from overwriting the pending challenge. The challenge reload starts a fresh provider after verification, preserving the validated local `redirectTo`. Keep MFA-aware continuation in customized registry authentication handlers; never assume a primary response creates a session. The portable SDK `SignIn` already implements an inline challenge and remains usable without this optional UI entry.

Use the portable SDK `SecuritySettings` for session management, or adapt the official registry `ActiveSessions` to `/api/allauth/sdk/sessions` and `/api/allauth/sdk/sessions/revoke`. These endpoints use opaque session IDs. Do not use the official native token-based session/multi-session controls with the proxy: credential fields are deliberately stripped, and they cannot authorize session revocation.

The existing `@allauth/react` components remain usable without Better Auth UI. The optional entry is a provider integration, not a bundled copy of the console's app-specific registry files.

Password rules are available in the same-origin `/api/allauth/sdk/config` response as
`passwordPolicy`: `minLength`, `maxLength`, `requireUppercase`, `requireLowercase`,
`requireNumber` and `requireSymbol`. Pass the effective length bounds to the upstream
provider's `emailAndPassword` settings and use the rules in any custom signup/reset/
change-password component. The `AllAuthUIProvider` wrapper leaves registry components
and their form validation in the consuming application. Existing sign-in passwords
must not be validated against new-password requirements. The bundled `SignUp`,
`ResetPassword` and account forms consume these settings automatically.

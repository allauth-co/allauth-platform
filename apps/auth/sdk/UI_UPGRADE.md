# Upgrade an embedding app from SDK v1 to v2

SDK v2 provides its own React components and cookie-based client. Apps already
using `AllAuthProvider` and the portable components can keep their imports and
props. The `@allauth/react/ui` entry now exports the same first-party components
and context as `@allauth/react`.

## Replace the optional registry integration

1. Replace `AllAuthUIProvider` with `AllAuthProvider`. Keep the same
   `basePath`, and map the old `redirectTo` to `afterSignInUrl`.
   Set `afterSignUpUrl` separately if registration has a different destination.
2. Replace the registry's sign-in, sign-up and recovery views with `SignIn`,
   `SignUp`, `ForgotPassword` and `ResetPassword`. Use `AccountSettings`
   or the portable profile and organization components for account settings.
3. Keep the provider above these views and the account area. Import
   `@allauth/react/styles.css` once in your app layout. Use `--allauth-*`
   variables to theme the first-party components.
4. Remove the old registry provider, plugins and views after replacing them.
   Remove the Better Auth, Better Auth UI and TanStack Query packages only if
   the rest of your application has no imports from them. Keep the registry's
   notices with any code you retain.

```tsx
"use client";

import { AllAuthProvider, SignIn } from "@allauth/react/ui";

export function SignInPage() {
  return (
    <AllAuthProvider
      basePath="/api/allauth"
      signInUrl="/sign-in"
      afterSignInUrl="/account"
      afterSignUpUrl="/account"
      profileUrl="/account"
    >
      <SignIn
        passkeySignIn
        signUpUrl="/sign-up"
        forgotPasswordUrl="/forgot-password"
      />
    </AllAuthProvider>
  );
}
```

The old `basePaths`, router adapters, provider-plugin options and
`socialProviders` props belong to the registry provider. Set your local
page URLs on the first-party components. By default, `AllAuthProvider` reads the
enabled sign-in options, branding and password policy from the selected
environment through `/api/allauth/sdk/config`. Set up Google, Apple and Microsoft
on the server for each environment.

If your app changes the server proxy's project binding at runtime while keeping
the same path, give the provider a new React `key` after the server rebind has
completed. This replaces the client and clears the previous project's component
state. A browser-side key has no effect on which project the server authorizes.

## Keep the same sign-in and account routes

- `SignIn` renders the authenticator or backup-code challenge inline. Point a
  full-page challenge landing route at the same `SignIn` component if you
  already use one, and carry only validated local return destinations. The
  server still requires successful verification before completing sign-in.
- Set `passkeySignIn` on `SignIn` to offer an explicit passkey button. Use the
  existing origin and relying-party ID so enrolled credentials remain usable.
  `AccountSettings` includes passkey enrolment, MFA and safe session controls.
  A custom form can request browser autofill via
  `client.signIn.passkey({ autoFill: true })` with a compatible
  `autoComplete="username webauthn"` input. Manage the request lifecycle with
  `fetchOptions.signal`, and check pending MFA before navigating.
- Keep the signed same-origin proxy and its existing mount. Keep the proxy
  secret and OAuth credentials server-side. If connected-app support is enabled,
  keep `supportAccess` on the shared provider and the matching proxy option.
- Custom forms can use `useAllAuth().client`. Handle `{ data, error }` results
  and pending MFA before navigating after a primary sign-in.

SDK v1 archives and their documentation remain available from [AllAuth SDK
downloads](https://allauth.co/sdk). Upgrading the application is a separate step
from deploying an AllAuth server release.

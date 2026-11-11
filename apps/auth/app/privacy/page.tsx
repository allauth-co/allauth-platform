import type { Metadata } from "next";

export const metadata: Metadata = { title: "Privacy information" };

export default function PrivacyPage() {
  return (
    <article className="mx-auto max-w-2xl space-y-7 text-sm leading-7">
      <header><h1 className="text-3xl font-semibold tracking-tight">Privacy information</h1><p className="mt-3 text-muted-foreground">AllAuth provides sign-in, account security and organization access for connected applications.</p></header>
      <section><h2 className="text-lg font-medium">Information used for authentication</h2><p>AllAuth stores your account name, email address and profile image, connected login-provider identifiers, organization memberships and roles. Passwords are stored as hashes. Depending on the security features you enable, the service also stores passkey public credentials and two-factor authentication settings. Session records include security information such as timestamps, IP addresses and browser details.</p></section>
      <section><h2 className="text-lg font-medium">Google and other login providers</h2><p>When you choose a social login provider, AllAuth requests your basic profile and email address to authenticate your account and link the chosen login method. Google login requests only OpenID, profile and email permissions. This login does not request access to your Gmail messages, Drive files or Calendar.</p></section>
      <section><h2 className="text-lg font-medium">Connected applications and organizations</h2><p>Registered applications receive the identity information you authorize during sign-in. Organization owners and authorized administrators can manage membership and access. Administrative actions, including support impersonation, are recorded for security and accountability. Each connected application provides its own information about its use of your data.</p></section>
      <section><h2 className="text-lg font-medium">Hosting and security</h2><p>The service uses hosting, database and transactional email providers to operate authentication and deliver account-security messages. Access to account-management functions is controlled by authentication and role permissions. Account information is retained to provide access and meet operational and security needs.</p></section>
      <section><h2 className="text-lg font-medium">Account access and requests</h2><p>You can review your profile and active sessions in account settings. For questions about account information, deletion requests or this service, contact <a className="underline underline-offset-4" href="mailto:tom@onsavii.com">tom@onsavii.com</a>.</p></section>
    </article>
  );
}

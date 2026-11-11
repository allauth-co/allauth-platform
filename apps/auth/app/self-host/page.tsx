import Link from "next/link";
import { PublicDocsFrame } from "@/components/marketing/public-docs";
import { publicSdkMetadata } from "@/lib/public-sdk";
import { platformRepositoryUrl } from "@/lib/public-site";
import "@/components/marketing/commercial.css";

export const metadata = publicSdkMetadata("Self-host AllAuth — the complete authentication platform", "Run the complete MIT-licensed AllAuth platform on your own infrastructure with all features, or choose managed hosting from $9.99 USD per workspace per month.", "/self-host");

export default function SelfHostPage() {
	return <PublicDocsFrame><header className="public-docs-heading"><p className="homepage-eyebrow">YOUR INFRASTRUCTURE. YOUR CONTROL.</p><h1>Run AllAuth yourself.</h1><p>The complete platform is available under the MIT license. Self-hosted instances include all features without an AllAuth subscription; you pay for and operate your own infrastructure and external providers.</p><div className="public-docs-links"><a href={platformRepositoryUrl}>Explore the platform source</a><a href={`${platformRepositoryUrl}/blob/main/docs/SELF_HOSTING.md`}>Read the deployment guide</a></div></header>
		<section className="public-docs-section"><h2>What you run</h2><p>AllAuth’s application, console and authentication service run with Node.js and PostgreSQL. The source includes its Docker build, database migrations and React SDK. Separate Development and Production environments remain available.</p><p>Bring your own domain, credentials and transactional email provider. Optional asset storage and custom-domain routing need their own configuration. Provider accounts, message fees, hosting, backups and upgrades remain your responsibility.</p></section>
		<section className="public-docs-section"><h2>Open source, including the useful parts</h2><p>Self-hosting includes attribution removal, larger organizations and unrestricted monthly impersonation allowance. Authentication permissions, audit events and security checks still apply. MIT allows commercial use and modification, with the required license notices retained.</p><p>AllAuth is built on Better Auth. Upstream and third-party notices remain with their respective code. The <a href={platformRepositoryUrl}>platform repository</a> includes the complete service, its required packages and tests, and the self-hosting deployment files.</p></section>
		<section className="public-docs-section"><h2>Prefer someone else to run it?</h2><p>Use hosted AllAuth to start free, then upgrade your workspace for $9.99 USD per month plus applicable tax. We operate the service; you integrate authentication into your application.</p><div className="public-docs-links"><Link href="/pricing">Compare hosted plans</Link><Link href="/sdk/quickstart">Explore the SDK</Link><Link href="/sign-up" prefetch={false}>Create a workspace</Link></div></section>
	</PublicDocsFrame>;
}

import Link from "next/link";
import { PublicDocsFrame } from "@/components/marketing/public-docs";
import { publicSdkMetadata } from "@/lib/public-sdk";

export const metadata = publicSdkMetadata("AllAuth hosted fair use", "Plain-language fair-use rules for AllAuth hosted authentication, organization membership and impersonation. No automatic usage overage charges; best-effort support.", "/fair-use");

export default function FairUsePage() {
	return <PublicDocsFrame><header className="public-docs-heading"><p className="homepage-eyebrow">HOSTED FAIR USE</p><h1>Useful limits. A predictable bill.</h1><p>AllAuth Pro removes the plan’s organization-member and monthly impersonation quotas. Hosting still runs on shared resources, and security protections apply to every plan.</p></header>
		<section className="public-docs-section"><h2>Use AllAuth for your applications</h2><p>Normal production authentication and legitimate support work are welcome. Do not use the hosted service for credential attacks, unsolicited messaging, bulk account farming or deliberate attempts to exhaust shared resources. Keep support access authorized and respect your users’ data.</p><p>Rate limits, session expiry, authorization and abuse protections remain active on Pro. Unlimited does not mean unlimited request throughput, email delivery, asset storage or exemption from security controls.</p></section>
		<section className="public-docs-section"><h2>No surprise overage charges</h2><p>We do not automatically bill per user, organization member, impersonation or extra request. If a workload needs materially more capacity, we will discuss capacity, a suitable arrangement or self-hosting. An upgrade or extra paid arrangement requires your agreement.</p><p>We may rate-limit abusive traffic or pause affected functionality to protect the service and its users. For legitimate capacity concerns, we aim to contact the workspace owner before restricting access.</p></section>
		<section className="public-docs-section"><h2>Support and external services</h2><p>Support is best effort, with no guaranteed response time or uptime SLA on these plans. Your separately configured providers can charge their own fees. Enterprise certification, enterprise support commitments and SMS delivery are not implied by an AllAuth subscription.</p><p>For capacity or account questions, contact <a href="mailto:tom@onsavii.com">tom@onsavii.com</a>. You can also <Link href="/self-host">run the platform yourself</Link>.</p></section>
	</PublicDocsFrame>;
}

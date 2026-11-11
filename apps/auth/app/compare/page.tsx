import Link from "next/link";
import { PublicDocsFrame } from "@/components/marketing/public-docs";
import { competitors, competitorCheckedAt } from "@/lib/commercial/competitors";
import { publicSdkMetadata } from "@/lib/public-sdk";
import "@/components/marketing/commercial.css";

export const metadata = publicSdkMetadata("Compare AllAuth with Clerk, Auth0 and Supabase", "Compare AllAuth's $9.99 USD workspace plan with Clerk, Auth0 and Supabase using dated primary sources, equivalent billing periods and honest product tradeoffs.", "/compare");

export default function ComparePage() {
	return <PublicDocsFrame><header className="public-docs-heading"><p className="homepage-eyebrow">FIND YOUR FIT</p><h1>Authentication without the pricing puzzle.</h1><p>Compare the features you need and the things each bill includes. AllAuth Pro is $9.99 USD per workspace per month plus applicable tax. Other platforms may include broader services or enterprise capabilities.</p></header><div className="commercial-grid">{Object.entries(competitors).map(([slug, competitor]) => <section className="commercial-plan" key={slug}><h2>AllAuth vs {competitor.name}</h2><p>{competitor.strength}</p><div className="public-docs-links"><Link href={`/compare/${slug}`}>Read the comparison</Link></div></section>)}</div><section className="public-docs-section"><h2>Compare the same purchase</h2><p>Our comparisons use public list prices checked on <time dateTime={competitorCheckedAt}>11 November 2026</time>. They distinguish monthly billing from annual commitments, base plans from add-ons, and authentication from a full backend platform. Follow the linked primary sources for current terms.</p><p>For what AllAuth includes, see <Link href="/pricing">pricing</Link> and <Link href="/fair-use">fair use</Link>. If you want to operate the service yourself, explore <Link href="/self-host">self-hosting</Link>.</p></section></PublicDocsFrame>;
}

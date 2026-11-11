import Link from "next/link";
import { competitors, competitorCheckedAt } from "@/lib/commercial/competitors";
import type { CompetitorSlug } from "@/lib/commercial/competitors";
import { commercialPlans } from "@/lib/commercial/plans";
import { PublicDocsFrame } from "./public-docs";
import "./commercial.css";

/** Comparisons keep facts, sources and dates together and acknowledge different product scopes. */
export function CompetitorPage({ slug }: { slug: CompetitorSlug }) {
	const competitor = competitors[slug];
	return <PublicDocsFrame>
		<header className="public-docs-heading"><p className="homepage-eyebrow">COMPARE AUTHENTICATION</p><h1>AllAuth vs {competitor.name}</h1><p>AllAuth is a focused option for developers who want hosted authentication, larger organizations and support impersonation at a simple workspace price. {competitor.name} has its own strengths and a different pricing model.</p><p className="commercial-source-note">Pricing checked <time dateTime={competitorCheckedAt}>11 November 2026</time>. USD list prices before applicable tax. <a href={competitor.pricingUrl}>{competitor.name}’s current pricing</a> is the source of record.</p></header>
		<div className="public-docs-table-wrap"><table className="commercial-comparison"><caption className="sr-only">AllAuth and {competitor.name} pricing and product scope</caption><thead><tr><th scope="col">Consideration</th><th scope="col">AllAuth</th><th scope="col">{competitor.name}</th></tr></thead><tbody>
			<tr><th scope="row">Free plan</th><td>Up to {commercialPlans.free.organizationMemberLimit} members per end-user organization; {commercialPlans.free.monthlyImpersonationLimit} impersonations per workspace per UTC calendar month.</td><td>{competitor.freeSummary}</td></tr>
			<tr><th scope="row">Paid starting point</th><td>${commercialPlans.pro.monthlyPriceUsd.toFixed(2)} per workspace per month. Up to five applications, each with Development and Production.</td><td>{competitor.priceSummary}</td></tr>
			<tr><th scope="row">What the price covers</th><td>Authentication, account and organization management. Pro removes AllAuth attribution and includes unlimited organization members and impersonations under fair use.</td><td>{competitor.tradeoff}</td></tr>
		</tbody></table></div>
		{slug === "auth0" && <p className="commercial-source-note">The B2B entry price is also documented in <a href="https://auth0.com/blog/whatever-you-are-building-auth0-has-a-plan/">Auth0’s plan guide</a>. Its pricing selector distinguishes B2B from B2C.</p>}
		{slug === "clerk" && <section className="public-docs-section"><h2>A concrete monthly example</h2><p>A team needing no Clerk branding, more than 20 members in an organization, and unlimited impersonations would compare Clerk Pro at $25 plus Enhanced B2B at $100 and Enhanced Administration at $100: $225/month on monthly billing, before usage or other extras. The annual-billing equivalents are $20 + $85 + $85 = $190/month, paid annually.</p><p>AllAuth Pro includes those three capabilities for $9.99 USD per workspace per month plus applicable tax, subject to fair use. This example compares those capabilities; it does not claim the products have identical feature sets, support or scale.</p><p><a href={competitor.pricingUrl}>Source: Clerk pricing and add-on definitions</a>.</p></section>}
		<section className="public-docs-section"><h2>When {competitor.name} fits</h2><p>{competitor.strength}</p><h2>When AllAuth fits</h2><p>You want a small monthly authentication bill, app-level organizations and an optional path to self-hosting the complete platform. AllAuth’s current portable SDK targets React with a server-side proxy. Support is best effort; enterprise SLAs, certifications and configured SMS are not included.</p></section>
		<section className="public-docs-section"><h2>Plan a migration, then switch</h2><p>{competitor.migration}</p><p>Test sign-in, MFA, recovery, account linking, invitations and authorization in a separate environment. A comparison page is not a guarantee of one-click migration or password portability.</p><div className="public-docs-links"><Link href="/sdk/quickstart">Read the integration guide</Link><Link href="/pricing">See AllAuth plans</Link><Link href="/compare">Compare other options</Link></div></section>
	</PublicDocsFrame>;
}

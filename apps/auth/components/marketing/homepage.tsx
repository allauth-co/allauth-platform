import { ArrowRight, Check, Fingerprint, ShieldCheck, Users } from "lucide-react";
import Link from "next/link";
import { sdkReleases, platformReleases } from "@/lib/notifications/releases";
import { EnvironmentPreview } from "./environment-preview";
import { IdentityDemo } from "./identity-demo";
import { MarketingHeader } from "./site-header";
import { MarketingFooter } from "./site-footer";
import "./homepage.css";

/** AllAuth's public product homepage; examples never read account data. */
export function Homepage() {
	const latestSdk = sdkReleases[0];
	const latestPlatform = platformReleases[0];
	return (
		<div className="homepage">
			<a className="homepage-skip-link" href="#main-content">Skip to content</a>
			<MarketingHeader />
			<main id="main-content">
				<section className="homepage-hero" aria-labelledby="homepage-title">
					<div className="homepage-container homepage-hero-inner">
						<div className="homepage-hero-copy">
							<p className="homepage-eyebrow"><span /> IDENTITY AND ACCESS, SIMPLIFIED</p>
							<h1 id="homepage-title">Authentication<br />for <em>every app.</em><br /><span>Managed in one place.</span></h1>
							<p className="homepage-hero-description">Add branded sign-in, secure accounts and organization access to your app. Manage it all from one console.</p>
							<div className="homepage-hero-actions">
								<Link href="/sign-up" className="homepage-button homepage-button-primary" prefetch={false}>Get started <ArrowRight size={19} aria-hidden="true" /></Link>
								<a href="#how-it-works" className="homepage-button homepage-button-secondary">See how it works <ArrowRight size={18} aria-hidden="true" /></a>
							</div>
							<p className="homepage-built-on"><Check size={15} aria-hidden="true" /> Built on Better Auth</p>
						</div>
						<div className="homepage-hero-demo"><IdentityDemo /></div>
					</div>
				</section>
				<section id="product" className="homepage-product homepage-container" aria-labelledby="homepage-product-title">
					<h2 id="homepage-product-title">Everything behind a great sign-in.</h2>
					<div className="homepage-features">
						<article className="homepage-feature"><span className="homepage-feature-icon"><Fingerprint size={27} aria-hidden="true" /></span><div><h3>Branded sign-in</h3><p>Hosted or embedded account experiences, with your branding.</p></div></article>
						<article className="homepage-feature"><span className="homepage-feature-icon"><Users size={27} aria-hidden="true" /></span><div><h3>Users &amp; organizations</h3><p>Manage users, teams and roles in one place.</p></div></article>
						<article className="homepage-feature"><span className="homepage-feature-icon"><ShieldCheck size={27} aria-hidden="true" /></span><div><h3>Security &amp; control</h3><p>Passkeys, MFA and session management built into the flow.</p></div></article>
					</div>
				</section>
				<section id="how-it-works" className="homepage-how" aria-labelledby="homepage-how-title">
					<div className="homepage-container homepage-how-inner">
						<div className="homepage-how-copy">
							<p className="homepage-eyebrow">FROM FIRST CONNECTION TO LAUNCH</p>
							<h2 id="homepage-how-title">From development<br />to production.</h2>
							<p>Separate users, settings and credentials for each environment. One place to manage them.</p>
							<ol className="homepage-steps"><li><span>01</span> Create your workspace</li><li><span>02</span> Connect and test your app</li><li><span>03</span> Set up your production environment</li></ol>
						</div>
						<EnvironmentPreview />
					</div>
				</section>
				<section id="developers" className="homepage-container homepage-developers" aria-labelledby="homepage-developers-title">
					<div><p className="homepage-eyebrow">MADE FOR DEVELOPERS. BUILT FOR YOUR PRODUCT.</p><h2 id="homepage-developers-title">Your app. Your experience.</h2><p>Use hosted sign-in or embed account components. Connect each app to its own environment, and manage identity from AllAuth.</p></div>
					<Link href="/admin/setup-guide" className="homepage-setup-link" prefetch={false}>Explore the setup guide <ArrowRight size={20} aria-hidden="true" /></Link>
				</section>
				<section className="homepage-container homepage-releases" aria-labelledby="homepage-releases-title">
					<p className="homepage-eyebrow">SDK &amp; RELEASES</p>
					<h2 id="homepage-releases-title">Build with the latest AllAuth.</h2>
					<div className="homepage-release-grid">
						<article className="homepage-release-card">
							<p className="homepage-eyebrow">{`Latest SDK ${latestSdk.version}`}</p>
							<h3>{latestSdk.title}</h3>
							<p>{latestSdk.summary}</p>
							<div className="homepage-release-links"><Link href="/sdk">Explore the SDK</Link><a href={latestSdk.downloadUrl}>Download {latestSdk.version}</a><Link href={`/releases/${latestSdk.slug}`}>Release notes</Link><Link href="/sdk/quickstart">Quickstart</Link></div>
						</article>
						{latestPlatform && <article className="homepage-release-card">
							<p className="homepage-eyebrow">PLATFORM UPDATE</p>
							<h3>{latestPlatform.title}</h3>
							<p>{latestPlatform.summary}</p>
							<div className="homepage-release-links"><Link href={`/releases/${latestPlatform.slug}`}>Read the update</Link><Link href="/releases">All releases <ArrowRight size={16} aria-hidden="true" /></Link></div>
						</article>}
					</div>
				</section>
				<section className="homepage-cta" aria-labelledby="homepage-cta-title"><div className="homepage-container"><h2 id="homepage-cta-title">Give your app a better sign-in.</h2><p>Your branding. Secure accounts. Clear control.</p><Link href="/sign-up" className="homepage-button homepage-button-white" prefetch={false}>Get started <ArrowRight size={18} aria-hidden="true" /></Link></div></section>
			</main>
			<MarketingFooter />
		</div>
	);
}

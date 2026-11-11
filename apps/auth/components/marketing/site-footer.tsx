import Link from "next/link";
import { Logo } from "@/components/logo";
import { platformRepositoryUrl, sdkRepositoryUrl } from "@/lib/public-site";

/** Public documentation and release history remain discoverable from every product page. */
export function MarketingFooter() {
	return <footer className="homepage-footer homepage-container">
		<div><Link href="/" aria-label="AllAuth home"><Logo className="homepage-footer-logo" /></Link><span>Identity and access</span></div>
		<nav aria-label="Footer navigation"><Link href="/pricing">Pricing</Link><Link href="/compare">Compare</Link><Link href="/self-host">Self-host</Link><a href="/#how-it-works">How it works</a><a href="/#developers">Developers</a><Link href="/sdk">SDK</Link><Link href="/releases">Releases</Link><a href={platformRepositoryUrl}>Platform source</a><a href={sdkRepositoryUrl}>SDK source</a><Link href="/fair-use">Fair use</Link><Link href="/privacy" prefetch={false}>Privacy</Link></nav>
	</footer>;
}

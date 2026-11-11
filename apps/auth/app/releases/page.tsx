import Link from "next/link";
import { PublicDocsFrame, ReleaseSummary } from "@/components/marketing/public-docs";
import { jsonLd, publicReleases, publicReleaseUrl, publicSdkMetadata } from "@/lib/public-sdk";

export const metadata = publicSdkMetadata("AllAuth SDK and platform release notes", "Explore AllAuth SDK versions and platform updates, with permanent release notes, verified downloads, source tags and archive provenance.", "/releases");

/** Public history includes archived packages without creating account or email announcements. */
export default function ReleasesPage() {
	return <PublicDocsFrame>
		<header className="public-docs-heading"><p className="homepage-eyebrow">ALLAUTH RELEASE HISTORY</p><h1>SDK and platform releases</h1><p>SDK releases and platform updates, with permanent notes and the evidence behind them.</p><div className="public-docs-links"><Link href="/sdk">SDK downloads</Link><Link href="/sdk/quickstart">Install and upgrade</Link><a href="/releases/feed.xml">RSS feed</a><a href="/releases/feed.json">JSON feed</a></div></header>
		<p className="public-docs-note">Historical SDK notes are reconstructed from preserved packages. Original publication dates are shown only when verified.</p>
		<section aria-label="Release history">{publicReleases.map(release => <ReleaseSummary key={release.id} release={release} />)}</section>
		<script type="application/ld+json" dangerouslySetInnerHTML={{ __html: jsonLd({ "@context": "https://schema.org", "@type": "ItemList", name: "AllAuth release history", itemListElement: publicReleases.map((release, index) => ({ "@type": "ListItem", position: index + 1, name: release.title, url: publicReleaseUrl(release) })) }) }} />
	</PublicDocsFrame>;
}

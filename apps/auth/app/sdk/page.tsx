import Link from "next/link";
import { PublicDocsFrame, ReleaseDate, ReleaseLinks } from "@/components/marketing/public-docs";
import { sdkReleases } from "@/lib/notifications/releases";
import { jsonLd, publicSdkMetadata, releaseStructuredData } from "@/lib/public-sdk";
import { sdkRepositoryUrl } from "@/lib/public-site";

export const metadata = publicSdkMetadata("AllAuth React SDK downloads, source and version history", "Install the AllAuth React SDK for branded sign-in, accounts and organisations. Explore every retained version, SHA256 checksum, source tag and release note.", "/sdk");

/** All package versions remain downloadable from their existing immutable same-host URLs. */
export default function SdkPage() {
	const latest = sdkReleases[0];
	return <PublicDocsFrame>
		<header className="public-docs-heading"><p className="homepage-eyebrow">THE ALLAUTH REACT SDK</p><h1>AllAuth React SDK</h1><p>Native React components for branded sign-in, profiles, security and organisations, connected through your application’s same-origin proxy.</p><div className="public-docs-links"><Link href="/sdk/quickstart">Get started</Link><a href={sdkRepositoryUrl}>Public source repository</a><Link href="/releases">Release history</Link></div></header>
		<section className="public-docs-section" aria-labelledby="latest-sdk"><div className="public-release-meta"><span className="public-docs-version">Latest SDK {latest.version}</span><span className="public-docs-compatibility">Backward compatible</span><ReleaseDate release={latest} /></div><h2 id="latest-sdk">{latest.title}</h2><p>{latest.summary}</p><ReleaseLinks release={latest} /><pre><code>{`pnpm add @allauth/react@${latest.downloadUrl}`}</code></pre><p>Use a matching React and React DOM version and the SDK’s declared peers. The <Link href="/sdk/quickstart">quickstart</Link> covers the server proxy, components and upgrades.</p></section>
		<section className="public-docs-section" aria-labelledby="all-sdk-versions"><h2 id="all-sdk-versions">All SDK versions</h2><p>Each version links to its exact source tag, immutable archive and checksum. Historical publication dates stay unverified unless supported by release records.</p><div className="public-docs-table-wrap"><table><caption className="sr-only">AllAuth React SDK package versions and verified downloads</caption><thead><tr><th scope="col">Version</th><th scope="col">Release record</th><th scope="col">Package and source</th></tr></thead><tbody>{sdkReleases.map(release => <tr key={release.id}><td><Link href={`/releases/${release.slug}`}><strong>{release.version}</strong></Link>{release === latest && <small>Latest release</small>}</td><td><ReleaseDate release={release} /><small>{release.compatibility === "backward-compatible" ? "Backward-compatible update" : "Reconstructed archive notes"}</small></td><td><a href={release.downloadUrl}>Download</a><a href={release.sourceUrl}>Source tag</a><Link href={`/releases/${release.slug}`}>Release notes</Link><small>SHA256 <code>{release.sha256}</code></small></td></tr>)}</tbody></table></div></section>
		<section className="public-docs-section" aria-labelledby="sdk-releases-follow"><h2 id="sdk-releases-follow">Follow future releases</h2><p>Watch <a href={`${sdkRepositoryUrl}/releases`}>GitHub releases</a>, subscribe to the <a href="/releases/feed.xml">RSS feed</a> or <a href="/releases/feed.json">JSON feed</a>, and manage SDK update emails in <Link href="/admin/notifications">AllAuth notifications</Link>.</p></section>
		<script type="application/ld+json" dangerouslySetInnerHTML={{ __html: jsonLd(releaseStructuredData(latest)) }} />
	</PublicDocsFrame>;
}

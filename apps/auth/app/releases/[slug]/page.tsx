import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { PublicDocsFrame, ReleaseCompatibility, ReleaseDate, ReleaseLinks } from "@/components/marketing/public-docs";
import { jsonLd, publicReleases, publicSdkMetadata, releaseStructuredData, verifiedReleaseDate } from "@/lib/public-sdk";

interface ReleasePageProps { params: Promise<{ slug: string }> }
export const dynamicParams = false;
export function generateStaticParams() { return publicReleases.map(release => ({ slug: release.slug })); }

export async function generateMetadata({ params }: ReleasePageProps): Promise<Metadata> {
	const { slug } = await params;
	const release = publicReleases.find(item => item.slug === slug);
	if (!release) notFound();
	const metadata = publicSdkMetadata(`${release.title} | AllAuth`, release.summary, `/releases/${release.slug}`);
	const publishedAt = verifiedReleaseDate(release);
	return { ...metadata, openGraph: { ...metadata.openGraph, type: "article", ...(publishedAt ? { publishedTime: publishedAt } : {}) } };
}

/** Permanent version pages retain archive provenance and omit unverified original dates. */
export default async function ReleasePage({ params }: ReleasePageProps) {
	const { slug } = await params;
	const release = publicReleases.find(item => item.slug === slug);
	if (!release) notFound();
	return <PublicDocsFrame>
		<nav aria-label="Breadcrumb" className="public-docs-breadcrumb"><Link href="/">AllAuth</Link><span aria-hidden="true">/</span><Link href="/releases">Releases</Link><span aria-hidden="true">/</span><span>{release.kind === "sdk" ? `SDK ${release.version}` : "Platform update"}</span></nav>
		<article>
			<header className="public-docs-heading"><div className="public-release-meta"><span className="public-docs-version">{release.kind === "sdk" ? `SDK ${release.version}` : "Platform update"}</span><ReleaseDate release={release} /><ReleaseCompatibility release={release} /></div><h1>{release.title}</h1><p>{release.summary}</p></header>
			{release.kind === "sdk" && <ReleaseLinks release={release} />}
			<section className="public-docs-section" aria-labelledby="release-changes"><h2 id="release-changes">What changed</h2><ul>{release.notes.map(note => <li key={note}>{note}</li>)}</ul></section>
			{release.kind === "sdk" && <>
				<section className="public-docs-section" aria-labelledby="release-compatibility"><h2 id="release-compatibility">Compatibility and upgrading</h2>{release.compatibility === "backward-compatible" ? <p>This release preserves existing APIs, sign-in flows and organisation permissions. Update the pinned SDK and its same-origin proxy together, then test and deploy your application.</p> : release.compatibility === "migration-required" ? <p>Upgrading requires application changes. Review the upgrade guide before changing the SDK pin. Your installed version continues to work.</p> : <p>These historical notes describe the retained package source. Review its archived README and your integration before choosing a version; a full compatibility assessment was not retained.</p>}<div className="public-docs-links"><Link href="/sdk/quickstart">Install and upgrade guide</Link><Link href="/sdk">Compare SDK versions</Link></div></section>
				<section className="public-docs-section" aria-labelledby="release-download"><h2 id="release-download">Verified package</h2><p>The versioned archive keeps its original URL. Verify the downloaded file against this SHA256 checksum.</p><p><a href={release.downloadUrl}>{release.downloadUrl}</a></p><code className="public-docs-checksum">{release.sha256}</code></section>
			</>}
			<section className="public-docs-section" aria-labelledby="release-provenance"><h2 id="release-provenance">Release provenance</h2>{release.provenance.map((item, index) => <div className="public-docs-provenance" key={`${item.kind}-${index}`}><h3>{item.kind.replaceAll("-", " ")}</h3><p>{item.details}</p>{item.files.length > 0 && <p>Reviewed package files: {item.files.map((file, fileIndex) => <span key={file}>{fileIndex > 0 && ", "}{release.kind === "sdk" ? <a href={`${release.sourceUrl.replace("/tree/", "/blob/")}/${file.split("/").map(encodeURIComponent).join("/")}`}><code>{file}</code></a> : <code>{file}</code>}</span>)}</p>}</div>)}</section>
		</article>
		<script type="application/ld+json" dangerouslySetInnerHTML={{ __html: jsonLd(releaseStructuredData(release)) }} />
	</PublicDocsFrame>;
}

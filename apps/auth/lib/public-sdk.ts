import type { Metadata, MetadataRoute } from "next";
import { sdkReleases } from "./notifications/releases";
import { platformReleases } from "./notifications/releases";
import type { PlatformRelease, SdkRelease } from "./notifications/releases";
import { commercialPublicPaths, publicSiteOrigin } from "./public-site";

export type PublicRelease = SdkRelease | PlatformRelease;
export const publicReleases: readonly PublicRelease[] = [...sdkReleases, ...platformReleases].sort((left, right) => (verifiedReleaseDate(right) ? Date.parse(verifiedReleaseDate(right)!) : 0) - (verifiedReleaseDate(left) ? Date.parse(verifiedReleaseDate(left)!) : 0));

/** Every SDK version owns a permanent page while its original download URL stays unchanged. */
export function publicReleaseUrl(release: Pick<PublicRelease, "slug">): string {
	return `${publicSiteOrigin}/releases/${encodeURIComponent(release.slug)}`;
}

/** Archive timestamps and reconstruction dates are not original publication dates. */
export function verifiedReleaseDate(release: PublicRelease): string | undefined {
	return release.dateConfidence === "known" && release.publishedAt && Number.isFinite(Date.parse(release.publishedAt)) ? release.publishedAt : undefined;
}

/** Versioned links retain their recorded repository when current ownership or navigation changes. */
export function sdkReleaseRepositoryUrl(release: Pick<SdkRelease, "sourceUrl">): string {
	const source = new URL(release.sourceUrl);
	return `${source.origin}${source.pathname.split("/tree/")[0]}`;
}

/** Canonical metadata is shared by the public SDK and release pages. */
export function publicSdkMetadata(title: string, description: string, path: string): Metadata {
	const canonical = `${publicSiteOrigin}${path}`;
	return {
		title: { absolute: title }, description, alternates: { canonical, types: {
			"application/rss+xml": [{ url: `${publicSiteOrigin}/releases/feed.xml`, title: "AllAuth releases" }],
			"application/feed+json": [{ url: `${publicSiteOrigin}/releases/feed.json`, title: "AllAuth releases" }],
		} },
		robots: { index: true, follow: true },
		openGraph: { title, description, url: canonical, type: "website", siteName: "AllAuth" },
		twitter: { card: "summary", title, description },
	};
}

/** Dates are emitted only when supported by release provenance. */
export function releaseStructuredData(release: PublicRelease) {
	const publishedAt = verifiedReleaseDate(release);
	if (release.kind === "platform") return {
		"@context": "https://schema.org", "@type": "TechArticle", headline: release.title, description: release.summary,
		url: publicReleaseUrl(release), publisher: { "@type": "Organization", name: "AllAuth", url: publicSiteOrigin },
		...(publishedAt ? { datePublished: publishedAt } : {}),
	};
	return {
		"@context": "https://schema.org", "@type": "SoftwareSourceCode",
		"@id": `${publicReleaseUrl(release)}#sdk`, name: release.title, description: release.summary,
		url: publicReleaseUrl(release), version: release.version, programmingLanguage: "TypeScript", runtimePlatform: "React",
		codeRepository: sdkReleaseRepositoryUrl(release), downloadUrl: release.downloadUrl,
		...(publishedAt ? { datePublished: publishedAt } : {}),
	};
}

/** Serialize public catalog text safely inside JSON-LD script elements. */
export function jsonLd(value: unknown): string {
	return JSON.stringify(value).replaceAll("<", "\\u003c");
}

/** Sitemap entries are canonical pages; unverified edit and publication dates are omitted. */
export function publicSdkSitemap(): MetadataRoute.Sitemap {
	return ["/", ...commercialPublicPaths, "/sdk", "/sdk/quickstart", "/releases", "/privacy", ...publicReleases.map(release => `/releases/${release.slug}`)].map(path => ({ url: `${publicSiteOrigin}${path}` }));
}

/** JSON Feed preserves historical entries without manufacturing their publication dates. */
export function sdkJsonFeed(releases: readonly PublicRelease[] = publicReleases) {
	return {
		version: "https://jsonfeed.org/version/1.1", title: "AllAuth releases",
		home_page_url: `${publicSiteOrigin}/releases`, feed_url: `${publicSiteOrigin}/releases/feed.json`,
		description: "AllAuth SDK and platform release notes, immutable downloads and source provenance.", language: "en",
		items: releases.map(release => ({
			id: publicReleaseUrl(release), url: publicReleaseUrl(release), title: release.title,
			content_text: [release.summary, ...release.notes, ...release.provenance.map(item => item.details)].join("\n\n"),
			...(verifiedReleaseDate(release) ? { date_published: verifiedReleaseDate(release) } : {}),
			...(release.kind === "sdk" ? { attachments: [{ url: release.downloadUrl, mime_type: "application/gzip", title: `AllAuth React SDK ${release.version}` }] } : {}),
			_allauth: { kind: release.kind, ...(release.kind === "sdk" ? { version: release.version, sha256: release.sha256, source_url: release.sourceUrl } : {}), compatibility: release.compatibility, date_confidence: release.dateConfidence, provenance: release.provenance },
		})),
	};
}

function xml(value: string): string {
	return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&apos;");
}

/** RSS publication dates are optional; unknown historical dates remain absent. */
export function sdkRssFeed(releases: readonly PublicRelease[] = publicReleases): string {
	return `<?xml version="1.0" encoding="UTF-8"?>\n<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom"><channel><title>AllAuth releases</title><link>${publicSiteOrigin}/releases</link><description>AllAuth SDK and platform release notes, immutable downloads and source provenance.</description><language>en</language><atom:link href="${publicSiteOrigin}/releases/feed.xml" rel="self" type="application/rss+xml"/>${releases.map(release => {
		const publishedAt = verifiedReleaseDate(release), url = xml(publicReleaseUrl(release));
		return `<item><title>${xml(release.title)}</title><link>${url}</link><guid isPermaLink="true">${url}</guid><description>${xml([release.summary, ...release.notes, ...release.provenance.map(item => item.details)].join("\n\n"))}</description>${publishedAt ? `<pubDate>${new Date(publishedAt).toUTCString()}</pubDate>` : ""}</item>`;
	}).join("")}</channel></rss>`;
}

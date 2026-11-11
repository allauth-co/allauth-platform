import Link from "next/link";
import type { ReactNode } from "react";
import type { SdkRelease } from "@/lib/notifications/releases";
import { publicReleaseUrl, verifiedReleaseDate } from "@/lib/public-sdk";
import type { PublicRelease } from "@/lib/public-sdk";
import { sdkRepositoryUrl } from "@/lib/public-site";
import { MarketingFooter } from "./site-footer";
import { MarketingHeader } from "./site-header";
import "./homepage.css";
import "./sdk.css";

/** Server-rendered public SDK pages use the product frame rather than an account session. */
export function PublicDocsFrame({ children }: { children: ReactNode }) {
	return <div className="homepage public-docs"><a className="homepage-skip-link" href="#main-content">Skip to content</a><MarketingHeader /><main id="main-content" className="homepage-container public-docs-main">{children}</main><MarketingFooter /></div>;
}

export function ReleaseDate({ release }: { release: PublicRelease }) {
	const date = verifiedReleaseDate(release);
	return date ? <time dateTime={date}>{new Date(date).toLocaleDateString("en", { year: "numeric", month: "long", day: "numeric", timeZone: "UTC" })}</time> : <span>Original publication date unverified</span>;
}

export function ReleaseLinks({ release }: { release: SdkRelease }) {
	return <div className="public-docs-links"><a href={release.downloadUrl}>Download {release.version}</a><a href={release.sourceUrl}>Source at v{release.version}</a><a href={`${sdkRepositoryUrl}/releases/tag/v${release.version}`}>GitHub release</a></div>;
}

export function ReleaseSummary({ release }: { release: PublicRelease }) {
	return <article id={release.slug} className="public-release-summary">
		<div className="public-release-meta"><span className="public-docs-version">{release.kind === "sdk" ? `SDK ${release.version}` : "Platform update"}</span><ReleaseDate release={release} />{release.compatibility === "backward-compatible" && <span className="public-docs-compatibility">Backward compatible</span>}</div>
		<h2><Link href={new URL(publicReleaseUrl(release)).pathname}>{release.title}</Link></h2>
		<p>{release.summary}</p>
		{release.kind === "sdk" && !release.announce && <p className="public-docs-note">Historical notes reconstructed from preserved SDK archives.</p>}
		<div className="public-docs-links"><Link href={`/releases/${release.slug}`}>Read release notes</Link>{release.kind === "sdk" && <><a href={release.downloadUrl}>Download {release.version}</a><a href={release.sourceUrl}>Versioned source</a></>}</div>
	</article>;
}

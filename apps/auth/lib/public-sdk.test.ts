// @vitest-environment happy-dom
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import SdkPage, { metadata as sdkMetadata } from "@/app/sdk/page";
import SdkQuickstartPage, { metadata as quickstartMetadata } from "@/app/sdk/quickstart/page";
import ReleasesPage, { metadata as releasesMetadata } from "@/app/releases/page";
import ReleasePage, { generateMetadata, generateStaticParams } from "@/app/releases/[slug]/page";
import { GET as jsonFeed } from "@/app/releases/feed.json/route";
import { GET as rssFeed } from "@/app/releases/feed.xml/route";
import robots from "@/app/robots";
import sitemap from "@/app/sitemap";
import { sdkReleases, platformReleases } from "./notifications/releases";
import { jsonLd, publicReleases, publicReleaseUrl, releaseStructuredData, sdkJsonFeed, sdkRssFeed, verifiedReleaseDate } from "./public-sdk";
import { publicSiteOrigin, sdkRepositoryUrl } from "./public-site";

vi.mock("next/navigation", () => ({ notFound: () => { throw Error("not-found"); } }));
vi.mock("next-themes", () => ({ useTheme: () => ({ resolvedTheme: "light", setTheme: vi.fn() }) }));

function render(element: Parameters<typeof renderToStaticMarkup>[0]) { return renderToStaticMarkup(element); }
function structured(html: string): Record<string, unknown> {
	const source = html.match(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/)?.[1];
	expect(source).toBeDefined();
	return JSON.parse(source!) as Record<string, unknown>;
}

describe("public SDK and platform release history", () => {
	it("links every retained release from the public index and preserves original fragment anchors", () => {
		const html = render(createElement(ReleasesPage));
		expect(html.match(/<h1\b/g)).toHaveLength(1);
		expect(generateStaticParams()).toEqual(publicReleases.map(release => ({ slug: release.slug })));
		for (const release of publicReleases) {
			expect(html).toContain(`id="${release.slug}"`);
			expect(html).toContain(`href="/releases/${release.slug}"`);
			expect(html).toContain(release.title.replaceAll("&", "&amp;"));
		}
		expect(html).toContain('id="sdk-1-4-3"');
		expect(structured(html)["@type"]).toBe("ItemList");
	});

	it("lists all immutable SDK archive URLs, source tags and exact checksums", () => {
		const html = render(createElement(SdkPage));
		expect(html.match(/<h1\b/g)).toHaveLength(1);
		for (const release of sdkReleases) {
			expect(html).toContain(`href="${release.downloadUrl}"`);
			expect(html).toContain(`href="${release.sourceUrl}"`);
			expect(html).toContain(release.sha256);
			expect(release.downloadUrl).toBe(`${publicSiteOrigin}/sdk/allauth-react-${release.version}.tgz`);
			expect(release.sourceUrl).toBe(`${sdkRepositoryUrl}/tree/v${release.version}/packages/react`);
		}
		expect(html).toContain('href="/sdk/quickstart"');
	});

	it.each(publicReleases)("renders a complete permanent page for $slug with evidence-qualified dates", async release => {
		const html = render(await ReleasePage({ params: Promise.resolve({ slug: release.slug }) }));
		expect(html.match(/<h1\b/g)).toHaveLength(1);
		expect(html).toContain(release.title.replaceAll("&", "&amp;"));
		expect(html).toContain("What changed"); expect(html).toContain("Release provenance");
		for (const item of release.provenance) expect(html).toContain(item.details.replaceAll("&", "&amp;").replaceAll("'", "&#x27;"));
		const data = structured(html);
		if (verifiedReleaseDate(release)) expect(data.datePublished).toBe(release.publishedAt);
		else {
			expect(data).not.toHaveProperty("datePublished"); expect(data).not.toHaveProperty("dateModified");
			expect(html).toContain("Original publication date unverified"); expect(html).not.toContain("<time"); expect(html).not.toContain("1970");
		}
		if (release.kind === "sdk") {
			expect(data["@type"]).toBe("SoftwareSourceCode"); expect(data.version).toBe(release.version);
			expect(html).toContain(release.sha256); expect(html).toContain(release.downloadUrl); expect(html).toContain(release.sourceUrl);
			if (release.compatibility === "historical") expect(html).not.toContain("Backward compatible");
		} else {
			expect(data["@type"]).toBe("TechArticle"); expect(data).not.toHaveProperty("downloadUrl"); expect(data).not.toHaveProperty("codeRepository");
			expect(html).not.toContain("GitHub release"); expect(html).not.toContain("Download ");
		}
	});

	it("returns a real not-found boundary for unknown or malformed release slugs", async () => {
		for (const slug of ["missing", "../admin", "sdk-9-9-9"]) {
			await expect(ReleasePage({ params: Promise.resolve({ slug }) })).rejects.toThrow("not-found");
			await expect(generateMetadata({ params: Promise.resolve({ slug }) })).rejects.toThrow("not-found");
		}
	});

	it("gives every public page a unique canonical title and discoverable feeds", async () => {
		for (const [metadata, path] of [[sdkMetadata, "/sdk"], [quickstartMetadata, "/sdk/quickstart"], [releasesMetadata, "/releases"]] as const) {
			expect(metadata.alternates?.canonical).toBe(publicSiteOrigin + path);
			expect(metadata.robots).toEqual({ index: true, follow: true });
			expect(metadata.description?.length).toBeGreaterThan(50);
			expect(metadata.alternates?.types).toHaveProperty("application/rss+xml");
			expect(metadata.alternates?.types).toHaveProperty("application/feed+json");
		}
		const canonicals: string[] = [];
		for (const release of publicReleases) {
			const metadata = await generateMetadata({ params: Promise.resolve({ slug: release.slug }) });
			expect(metadata.title).toEqual({ absolute: `${release.title} | AllAuth` });
			expect(metadata.alternates?.canonical).toBe(publicReleaseUrl(release)); canonicals.push(String(metadata.alternates?.canonical));
			if (!verifiedReleaseDate(release)) expect(metadata.openGraph).not.toHaveProperty("publishedTime");
		}
		expect(new Set(canonicals).size).toBe(publicReleases.length);
	});

	it("builds a canonical public sitemap with no fabricated modification dates or private routes", () => {
		const entries = sitemap(), urls = entries.map(item => item.url);
		expect(new Set(urls).size).toBe(urls.length);
		for (const release of publicReleases) expect(urls).toContain(publicReleaseUrl(release));
		for (const path of ["/sdk", "/sdk/quickstart", "/releases"]) expect(urls).toContain(publicSiteOrigin + path);
		for (const entry of entries) { expect(entry.url).toMatch(/^https:\/\/allauth\.co\//); expect(entry.url).not.toMatch(/\/admin|\/api\/|\/account/); expect(entry).not.toHaveProperty("lastModified"); }
		expect(robots().sitemap).toBe(`${publicSiteOrigin}/sitemap.xml`);
		expect(robots().rules).toMatchObject({ allow: "/", disallow: expect.arrayContaining(["/api/", "/admin", "/account"]) });
	});

	it("serves JSON and RSS histories with every public entry and no invented historical publication dates", async () => {
		const json = jsonFeed(), rss = rssFeed();
		expect(json.headers.get("content-type")).toBe("application/feed+json; charset=utf-8");
		expect(rss.headers.get("content-type")).toBe("application/rss+xml; charset=utf-8");
		const body = await json.json() as ReturnType<typeof sdkJsonFeed>;
		expect(body.version).toBe("https://jsonfeed.org/version/1.1"); expect(body.items).toHaveLength(sdkReleases.length + platformReleases.length);
		const document = new DOMParser().parseFromString(await rss.text(), "application/xml");
		expect(document.querySelector("parsererror")).toBeNull();
		const items = [...document.querySelectorAll("item")]; expect(items).toHaveLength(publicReleases.length);
		for (const release of publicReleases) {
			const item = body.items.find(row => row.id === publicReleaseUrl(release))!;
			const xmlItem = items.find(row => row.querySelector("guid")?.textContent === publicReleaseUrl(release))!;
			expect(item.title).toBe(release.title);
			if (!verifiedReleaseDate(release)) { expect(item).not.toHaveProperty("date_published"); expect(xmlItem.querySelector("pubDate")).toBeNull(); }
			if (release.kind === "platform") expect(item).not.toHaveProperty("attachments");
		}
	});

	it("escapes release examples in RSS and JSON-LD without changing their content", () => {
		const sample = { ...sdkReleases[0], summary: 'Use <Code> & "quoted" values </script>' };
		const rss = sdkRssFeed([sample]);
		expect(rss).toContain("&lt;Code&gt; &amp; &quot;quoted&quot; values &lt;/script&gt;");
		expect(jsonLd(releaseStructuredData(sample))).not.toContain("</script>");
		expect(JSON.parse(jsonLd(releaseStructuredData(sample))).description).toBe(sample.summary);
	});

	it("publishes setup and upgrade guidance with the actual released archive and server-only proxy example", () => {
		const html = render(createElement(SdkQuickstartPage));
		expect(html.match(/<h1\b/g)).toHaveLength(1);
		expect(html).toContain(sdkReleases[0].downloadUrl);
		expect(html).toContain("app/api/allauth/[...all]/route.ts"); expect(html).toContain("createAllAuthProxy");
		expect(html).toContain("process.env.ALLAUTH_PROXY_SECRET"); expect(html).not.toContain("NEXT_PUBLIC_ALLAUTH_PROXY_SECRET");
		expect(html).toContain("Upgrading an existing app"); expect(html).toContain('id="upgrade"');
	});
});

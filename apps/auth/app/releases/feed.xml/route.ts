import { sdkRssFeed } from "@/lib/public-sdk";

export const dynamic = "force-static";
export function GET() {
	return new Response(sdkRssFeed(), { headers: { "content-type": "application/rss+xml; charset=utf-8", "cache-control": "public, max-age=300, stale-while-revalidate=3600", "x-content-type-options": "nosniff" } });
}

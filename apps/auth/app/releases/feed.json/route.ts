import { sdkJsonFeed } from "@/lib/public-sdk";

export const dynamic = "force-static";
export function GET() {
	return Response.json(sdkJsonFeed(), { headers: { "content-type": "application/feed+json; charset=utf-8", "cache-control": "public, max-age=300, stale-while-revalidate=3600", "x-content-type-options": "nosniff" } });
}

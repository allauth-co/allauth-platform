import path from "node:path";
import { fileURLToPath } from "node:url";
import { initOpenNextCloudflareForDev } from "@opennextjs/cloudflare";
import type { NextConfig } from "next";
import { PHASE_DEVELOPMENT_SERVER } from "next/constants";

const appDirectory = path.dirname(fileURLToPath(import.meta.url));

const nextConfig: NextConfig = {
	output: "standalone",
	// The hosted gateway signs the original path and query, including Next's RSC query.
	skipProxyUrlNormalize: true,
	// Include the official repository packages linked by this production service.
	outputFileTracingRoot: path.resolve(appDirectory, "../.."),
	outputFileTracingIncludes: {
		"/api/health": ["./migrations/*.sql"],
		"/api/admin/projects": ["./migrations/*.sql"],
	},
	images: { unoptimized: true },
};

export default async function configuration(phase: string) {
	if (phase === PHASE_DEVELOPMENT_SERVER && process.env.AUTH_RUNTIME !== "node")
		await initOpenNextCloudflareForDev();
	return nextConfig;
}

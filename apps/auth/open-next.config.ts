import { defineCloudflareConfig } from "@opennextjs/cloudflare";

// Authentication pages render per request; no ISR cache resources are required.
export default {
	...defineCloudflareConfig(),
	monorepoRoot: "../..",
};

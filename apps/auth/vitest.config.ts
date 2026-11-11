import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
	resolve: { alias: { "@": fileURLToPath(new URL(".", import.meta.url)) } },
	test: {
		include: [
			"components/management/**/*.test.ts",
			"lib/**/*.test.ts",
			"components/control/**/*.test.ts",
			"lib/control/**/*.test.ts",
			"sdk/**/*.test.ts",
			"workers/**/*.test.ts",
		],
		environment: "node",
	},
});

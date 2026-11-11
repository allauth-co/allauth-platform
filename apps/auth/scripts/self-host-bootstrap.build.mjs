import { fileURLToPath } from "node:url";
import { bundledNotices } from "./avatar-cleanup.build.mjs";

export default {
	entry: { bootstrap: fileURLToPath(new URL("./self-host-bootstrap.ts", import.meta.url)) },
	outDir: process.env.ALLAUTH_SELF_HOST_BUILD_DIR || fileURLToPath(new URL("../.next/self-host", import.meta.url)),
	format: ["esm"], platform: "node", target: "node22", dts: false, sourcemap: false, shims: true, clean: true,
	deps: { alwaysBundle: () => true, neverBundle: ["pg-native"], onlyBundle: false },
	hooks: { "build:done": ({ chunks, options }) => bundledNotices(chunks, options.outDir) },
};

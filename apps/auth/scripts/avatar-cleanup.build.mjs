import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";

export function bundledNotices(chunks, outDir) {
	const packages = new Map();
	for (const chunk of chunks) {
		for (const moduleId of Object.keys(chunk.modules || {})) {
			if (!moduleId.startsWith("/")) continue;
			let directory = dirname(moduleId);
			while (directory !== dirname(directory)) {
				const manifestPath = join(directory, "package.json");
				if (existsSync(manifestPath)) {
					const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
					if (manifest.name) {
						if (manifest.name === "@allauth/auth-service") break;
						const licenseNames = readdirSync(directory).filter((name) =>
							/^(license|copying)([.].*)?$/i.test(name),
						);
						let license = licenseNames
							.map((name) => readFileSync(join(directory, name), "utf8"))
							.join("\n");
						if (!license && existsSync(join(directory, "README.md"))) {
							const readme = readFileSync(join(directory, "README.md"), "utf8");
							const section =
								readme.match(
									/^##?\s+license\s*\n([\s\S]*?)(?=^##?\s|$(?![\s\S]))/im,
								)?.[1] || "";
							if (
								/copyright/i.test(section) &&
								/Permission is hereby granted/.test(section)
							)
								license = section;
						}
						const fallback =
							manifest.name.startsWith("@better-auth/") ||
							manifest.name === "better-auth";
						if (!license && !fallback)
							throw Error(
								"A bundled cleanup dependency has no license notice.",
							);
						packages.set(
							`${manifest.name}@${manifest.version}`,
							license ||
								readFileSync(
									new URL("./avatar-cleanup.LICENSE.md", import.meta.url),
									"utf8",
								),
						);
						break;
					}
				}
				directory = dirname(directory);
			}
		}
	}
	const notices = [...packages.entries()].sort(([left], [right]) =>
		left < right ? -1 : left > right ? 1 : 0,
	);
	writeFileSync(
		join(outDir, "THIRD_PARTY_NOTICES.txt"),
		notices.map(([name, license]) => `${name}\n${license}\n`).join("\n"),
	);
}

// tsdown 0.21.10 is already pinned by the official Better Auth build workspace.
// Bundle runtime dependencies so the scheduled command needs only Node 22.
export default {
	entry: {
		"avatar-cleanup": fileURLToPath(
			new URL("./avatar-cleanup.ts", import.meta.url),
		),
		"avatar-cleanup-runner": fileURLToPath(
			new URL("./avatar-cleanup-runner.ts", import.meta.url),
		),
	},
	outDir:
		process.env.ALLAUTH_AVATAR_CLEANUP_BUILD_DIR ||
		fileURLToPath(new URL("../.next/avatar-cleanup", import.meta.url)),
	format: ["esm"],
	platform: "node",
	target: "node22",
	dts: false,
	sourcemap: false,
	shims: true,
	clean: true,
	deps: {
		alwaysBundle: () => true,
		neverBundle: ["pg-native"],
		onlyBundle: false,
	},
	hooks: {
		"build:done": ({ chunks, options }) =>
			bundledNotices(chunks, options.outDir),
	},
};

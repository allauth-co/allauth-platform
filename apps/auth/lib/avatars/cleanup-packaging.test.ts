import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const repository = fileURLToPath(new URL("../../../../", import.meta.url));
const app = join(repository, "apps/auth");
const temporary = mkdtempSync(join(tmpdir(), "allauth-cleanup-package-"));
const executable = join(temporary, "avatar-cleanup.mjs");
const childEnvironment: NodeJS.ProcessEnv = {
	NODE_ENV: "test",
	EMAIL_FROM: "synthetic@fixture.invalid",
	BETTER_AUTH_SECRET: "synthetic-only-secret-at-least-thirty-two",
	BETTER_AUTH_URL: "https://synthetic.invalid",
	TRUSTED_ORIGINS: "https://synthetic.invalid",
};
beforeAll(() => {
	const result = spawnSync(
		"pnpm",
		[
			"--filter",
			"better-auth",
			"exec",
			"tsdown",
			"--config",
			join(app, "scripts/avatar-cleanup.build.mjs"),
		],
		{
			cwd: repository,
			encoding: "utf8",
			env: { ...process.env, ALLAUTH_AVATAR_CLEANUP_BUILD_DIR: temporary },
			timeout: 60000,
		},
	);
	expect(result.status, result.stderr + result.stdout).toBe(0);
}, 65000);
afterAll(() => rmSync(temporary, { recursive: true, force: true }));

function run(args: string[] = [], enabled?: string) {
	return spawnSync(process.execPath, [executable, ...args], {
		cwd: temporary,
		encoding: "utf8",
		env: {
			...childEnvironment,
			PATH: process.env.PATH,
			ALLAUTH_AVATAR_CLEANUP_ENABLED: enabled,
			DATABASE_URL: "postgres://synthetic.invalid/do-not-connect",
			ALLAUTH_ASSET_ORIGIN: "https://synthetic.invalid",
			ALLAUTH_AVATAR_SECRET:
				"synthetic-never-exported-secret-at-least-thirty-two",
		},
		timeout: 10000,
	});
}

describe("compiled production owned-avatar cleanup entry", () => {
	it.each([
		undefined,
		"false",
		"TRUE",
		"1",
	])("refuses enablement %s before loading the database/provider runner", (enabled) => {
		const launcherOnly = mkdtempSync(join(tmpdir(), "allauth-cleanup-off-"));
		try {
			cpSync(executable, join(launcherOnly, "avatar-cleanup.mjs"));
			const result = spawnSync(process.execPath, ["avatar-cleanup.mjs"], {
				cwd: launcherOnly,
				encoding: "utf8",
					env: { ...childEnvironment, ALLAUTH_AVATAR_CLEANUP_ENABLED: enabled },
				timeout: 3000,
			});
			expect(result.status).toBe(1);
			expect(result.stdout).toBe("");
			expect(result.stderr).toBe("Owned-avatar cleanup failed.\n");
		} finally {
			rmSync(launcherOnly, { recursive: true, force: true });
		}
	});
	it("refuses caller arguments before loading the runner even when enabled", () => {
		const result = run(["https://synthetic.invalid/owner"], "true");
		expect(result.status).toBe(1);
		expect(result.stderr).toBe("Owned-avatar cleanup failed.\n");
		expect(result.stdout).toBe("");
	});
	it("loads the bundled runtime with no host node_modules or database side effects", () => {
		const result = spawnSync(
			process.execPath,
			[
				"--input-type=module",
				"--eval",
				"await import('./avatar-cleanup-runner.mjs'); console.log('cleanup_module_loaded')",
			],
			{ cwd: temporary, encoding: "utf8", env: childEnvironment, timeout: 10000 },
		);
		expect(result.status, result.stderr).toBe(0);
		expect(result.stdout).toBe("cleanup_module_loaded\n");
		expect(result.stderr).toBe("");
	});
	it("production Docker copies the compiled directory and retains the normal server command", () => {
		const dockerfile = readFileSync(join(app, "Dockerfile"), "utf8");
		expect(dockerfile).toContain("scripts/avatar-cleanup.build.mjs");
		expect(dockerfile).toContain(
			"/app/apps/auth/.next/avatar-cleanup ./scripts/avatar-cleanup",
		);
		expect(dockerfile).toContain('CMD ["node", "server.js"]');
	});
	it("packages permission notices for the actual bundled runtime dependencies", () => {
		const notices = readFileSync(
			join(temporary, "THIRD_PARTY_NOTICES.txt"),
			"utf8",
		);
		expect(notices).toContain("pg@8.23.1");
		expect(notices).toContain("zod@4.5.4");
		expect(notices).toContain("@better-auth/core@");
		expect(notices).toContain("Permission is hereby granted");
	});
});

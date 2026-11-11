import { spawn, spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import type { Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import type { Pool } from "pg";
import { cleanupOwnedAvatars } from "./lifecycle";
import { avatarProtocol } from "./protocol";

const repository = fileURLToPath(new URL("../../../../", import.meta.url));
const temporary = mkdtempSync(join(tmpdir(), "allauth-cleanup-wire-"));
const marker = "SYNTHETIC_PRIVATE_CONNECTION_MARKER";
const environment: NodeJS.ProcessEnv = {
	NODE_ENV: "test",
	EMAIL_FROM: "synthetic@fixture.invalid",
	BETTER_AUTH_SECRET: "synthetic-only-secret-at-least-thirty-two",
	BETTER_AUTH_URL: "https://fixture.invalid",
	TRUSTED_ORIGINS: "https://fixture.invalid",
	ALLAUTH_AVATAR_CLEANUP_ENABLED: "true",
};
beforeAll(() => {
	// The operator can replay the same wire checks on files extracted from the final Docker image.
	if (process.env.ALLAUTH_AVATAR_TEST_COMPILED_DIR) {
		cpSync(process.env.ALLAUTH_AVATAR_TEST_COMPILED_DIR, temporary, {
			recursive: true,
		});
		return;
	}
	const result = spawnSync(
		"pnpm",
		[
			"--filter",
			"better-auth",
			"exec",
			"tsdown",
			"--config",
			join(repository, "apps/auth/scripts/avatar-cleanup.build.mjs"),
		],
		{
			cwd: repository,
			encoding: "utf8",
			timeout: 60000,
			env: { ...process.env, ALLAUTH_AVATAR_CLEANUP_BUILD_DIR: temporary },
		},
	);
	expect(result.status, result.stderr + result.stdout).toBe(0);
}, 65000);
afterAll(() => rmSync(temporary, { recursive: true, force: true }));

/** Synthetic PostgreSQL wire only; never opens a database or provider connection. */
async function wireScenario(
	mode: "idle" | "held" | "dispose" | "handshake" | "query" | "error-query",
	stop = false,
) {
	const sockets = new Set<Socket>();
	let accepted: (() => void) | undefined;
	const connected = new Promise<void>((resolve) => {
		accepted = resolve;
	});
	const server = createServer((socket) => {
		sockets.add(socket);
		socket.on("error", () => {});
		socket.on("close", () => sockets.delete(socket));
		accepted?.();
		let started = false;
		socket.on("data", () => {
			if (!started) {
				started = true;
				if (mode === "handshake") return;
				socket.write(
					Uint8Array.from([82, 0, 0, 0, 8, 0, 0, 0, 0, 90, 0, 0, 0, 5, 73]),
				);
				if (mode === "idle" || mode === "held")
					setTimeout(() => socket.destroy(), 150);
			} else if (mode === "error-query") {
				const fields = Buffer.from(
					`SERROR\0CXX000\0M${marker}\0D${marker}\0\0`,
				);
				const header = Buffer.alloc(5);
				header[0] = 69;
				header.writeInt32BE(fields.length + 4, 1);
				socket.write(
					Buffer.concat([header, fields, Buffer.from([90, 0, 0, 0, 5, 73])]),
				);
			}
		});
	});
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const address = server.address();
	if (!address || typeof address === "string")
		throw Error("Synthetic listener unavailable.");
	const url = `postgres://fixture:${marker}@127.0.0.1:${address.port}/fixture?sslmode=disable`;
	let args = [join(temporary, "avatar-cleanup.mjs")];
	if (mode === "idle" || mode === "held" || mode === "dispose") {
		const script = join(temporary, `probe-${mode}.mjs`);
		writeFileSync(
			script,
			`import {createCleanupDatabase} from './avatar-cleanup-runner.mjs';
const controller=new AbortController();
const database=createCleanupDatabase(process.env.DATABASE_URL,'public',controller);
const client=await database.pool.connect();
${mode === "idle" || mode === "dispose" ? "client.release();" : ""}
${mode === "dispose" ? "" : "if(!controller.signal.aborted)await new Promise(resolve=>controller.signal.addEventListener('abort',resolve,{once:true}));"}
${mode === "held" ? "client.release(true);" : ""}
await database.dispose();
${mode === "dispose" ? "await new Promise(resolve=>setTimeout(resolve,30));if(controller.signal.aborted)throw Error('Intentional disposal marked failure.');" : ""}
console.log('${mode === "dispose" ? "controlled_database_disposal" : "controlled_database_failure"}');
`,
		);
		args = [script];
	}
	const child = spawn(process.execPath, args, {
		cwd: temporary,
		env: { ...environment, DATABASE_URL: url },
		stdio: ["ignore", "pipe", "pipe"],
	});
	let stdout = "",
		stderr = "";
	child.stdout.on("data", (data) => {
		stdout += String(data);
	});
	child.stderr.on("data", (data) => {
		stderr += String(data);
	});
	const began = Date.now();
	const completion = new Promise<{
		code: number | null;
		signal: string | null;
	}>((resolve, reject) => {
		child.once("error", reject);
		child.once("exit", (code, signal) => resolve({ code, signal }));
	});
	const deadline = setTimeout(() => child.kill("SIGKILL"), 7000);
	try {
		if (stop) {
			await connected;
			await new Promise((resolve) => setTimeout(resolve, 80));
			child.kill("SIGTERM");
		}
		const result = await completion;
		return { ...result, stdout, stderr, elapsed: Date.now() - began };
	} finally {
		clearTimeout(deadline);
		child.kill("SIGKILL");
		for (const socket of sockets) socket.destroy();
		await new Promise<void>((resolve) => server.close(() => resolve()));
	}
}

describe("compiled cleanup connection failure boundaries", () => {
	it("does not mark intentional pool disposal as a connection failure", async () => {
		const result = await wireScenario("dispose");
		expect(result.signal).toBeNull();
		expect(result.code).toBe(0);
		expect(result.stdout).toBe("controlled_database_disposal\n");
		expect(result.stderr).toBe("");
	});
	it.each([
		"idle",
		"held",
	] as const)("contains a real pg %s disconnect without printing its client/config", async (mode) => {
		const result = await wireScenario(mode);
		expect(result.signal).toBeNull();
		expect(result.code).toBe(0);
		expect(result.stdout).toBe("controlled_database_failure\n");
		expect(result.stderr).toBe("");
		expect(result.stdout + result.stderr).not.toContain(marker);
	});
	it("bounds a stalled PG handshake and SIGTERM with a fixed failure", async () => {
		const result = await wireScenario("handshake", true);
		expect(result.signal).toBeNull();
		expect(result.code).toBe(1);
		expect(result.elapsed).toBeLessThan(3500);
		expect(result.stderr).toBe("Owned-avatar cleanup failed.\n");
		expect(result.stdout + result.stderr).not.toContain(marker);
	});
	it("cancels an acquired client waiting for a query on SIGTERM", async () => {
		const result = await wireScenario("query", true);
		expect(result.signal).toBeNull();
		expect(result.code).toBe(1);
		expect(result.elapsed).toBeLessThan(3500);
		expect(result.stderr).toBe("Owned-avatar cleanup failed.\n");
		expect(result.stdout + result.stderr).not.toContain(marker);
	});
	it("bounds an unanswered query without requiring shutdown", async () => {
		const result = await wireScenario("query");
		expect(result.signal).toBeNull();
		expect(result.code).toBe(1);
		expect(result.elapsed).toBeLessThan(5500);
		expect(result.stderr).toBe("Owned-avatar cleanup failed.\n");
		expect(result.stdout + result.stderr).not.toContain(marker);
	});
	it("never exports a raw PG ErrorResponse detail from the registry query", async () => {
		const result = await wireScenario("error-query");
		expect(result.signal).toBeNull();
		expect(result.code).toBe(1);
		expect(result.stderr).toBe("Owned-avatar cleanup failed.\n");
		expect(result.stdout + result.stderr).not.toContain(marker);
	});
});

describe("cleanup deadline reaches per-object transport and heartbeat", () => {
	it("does not acquire or request anything after cancellation", async () => {
		const controller = new AbortController();
		controller.abort();
		const connect = vi.fn();
		const fetch = vi.fn();
		vi.stubGlobal("fetch", fetch);
		try {
			await expect(
				cleanupOwnedAvatars(
					{ projectId: "", workspaceId: "", applicationId: "", schemaName: "" },
					{ connect } as unknown as Pool,
					{},
					25,
					undefined,
					controller.signal,
				),
			).rejects.toMatchObject({ statusCode: 503 });
			expect(connect).not.toHaveBeenCalled();
			expect(fetch).not.toHaveBeenCalled();
		} finally {
			vi.unstubAllGlobals();
		}
	});
	it("keeps erase intent retryable and never stamps healthy after an in-flight DELETE is cancelled", async () => {
		const controller = new AbortController();
		const scope = {
			projectId: "11111111-1111-4111-8111-111111111111",
			workspaceId: "22222222-2222-4222-8222-222222222222",
			applicationId: "33333333-3333-4333-8333-333333333333",
			schemaName: "allauth_project_" + "a".repeat(32),
		};
		const id = "44444444-4444-4444-8444-444444444444";
		const path = `/avatars/${scope.workspaceId}/${scope.applicationId}/${scope.projectId}/${id}.webp`;
		const statements: string[] = [];
		const release = vi.fn();
		const query = vi.fn(async (sql: string) => {
			statements.push(sql);
			if (sql.startsWith('SELECT "assetOrigin"'))
				return { rows: [{ assetOrigin: "https://assets.fixture.invalid" }] };
			if (sql.startsWith("SELECT *"))
				return {
					rows: [
						{
							id,
							objectPath: path,
							url: "https://assets.fixture.invalid" + path,
						},
					],
				};
			return { rows: [] };
		});
		const pool = {
			connect: async () => ({ query, release }),
		} as unknown as Pool;
		vi.stubGlobal("fetch", async (_url: string, options: RequestInit) => {
			if (options.method === "GET")
				return new Response(
					JSON.stringify({
						profileImageOwnershipAndDeletionProtocol: avatarProtocol,
					}),
					{ headers: { "cache-control": "private, no-store" } },
				);
			expect(options.signal).toBeDefined();
			controller.abort();
			return new Response(null, {
				status: 204,
				headers: { "cache-control": "private, no-store" },
			});
		});
		try {
			await expect(
				cleanupOwnedAvatars(
					scope,
					pool,
					{
						ALLAUTH_ASSET_ORIGIN: "https://assets.fixture.invalid",
						ALLAUTH_AVATAR_SECRET:
							"synthetic-avatar-protocol-secret-more-than-thirty-two",
					},
					25,
					undefined,
					controller.signal,
				),
			).rejects.toMatchObject({ statusCode: 503 });
			expect(
				statements.some(
					(sql) =>
						sql.includes("state='deleted'") || sql.includes('"healthyAt"='),
				),
			).toBe(false);
			expect(statements).toContain("ROLLBACK");
			expect(release).toHaveBeenCalledWith(true);
		} finally {
			vi.unstubAllGlobals();
		}
	});
});

import { mkdtemp, readFile, rm, stat, symlink, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { importClerkBatch, parseImportClerkArguments } from "./import-clerk.js";
import type { ToolRequest } from "./catalog.js";

const project = "communityapp-development", sourceInstance = "ins_fixture";
const passwordHash = "$2b$10$" + "a".repeat(53);
const user = { sourceUserId: "user_fixture", email: "fixture@example.com", emailVerified: true, name: "Fixture", updatedAt: "2026-10-29T00:00:00.000Z", passwordHash, passwordHasher: "bcrypt" };
const temporary: string[] = [];
async function fixture() {
	const directory = await mkdtemp(join(tmpdir(), "allauth-clerk-cli-")); temporary.push(directory);
	const input = join(directory, "input.json"), out = join(directory, "result.json");
	await writeFile(input, JSON.stringify({ sourceInstance, dryRun: true, users: [user] }), { mode: 0o600 });
	const response = (dryRun = true) => ({ project, projectId: "7046c686-3816-42ae-82e3-ad71b96d3282", sourceInstance, dryRun, created: dryRun ? 0 : 1, existing: 0, conflicts: 0,
		users: [{ sourceUserId: user.sourceUserId, sourceUpdatedAt: user.updatedAt, userId: "clerk_fixture", status: dryRun ? "would_create" : "created" }] });
	return { directory, input, out, response };
}
afterEach(async () => { await Promise.all(temporary.splice(0).map((directory) => rm(directory, { recursive: true, force: true }))); vi.unstubAllEnvs(); });

describe("private Clerk import command", () => {
	it("defaults to dry run, uses the named catalog operation and writes only safe private results", async () => {
		const state = await fixture(); const stdout = vi.fn();
		const request = vi.fn(async () => ({ ...state.response(), users: state.response().users.map((row) => ({ ...row, passwordHash, token: "never-return" })), passwordHash, privateMetadata: { secret: "never-return" } }));
		await importClerkBatch({ project, input: state.input, out: state.out, allowSensitive: true, readOnly: false, request, stdout });
		expect(request).toHaveBeenCalledWith(expect.objectContaining({ method: "POST", path: `/api/projects/${project}/auth/project-admin/import-clerk-users`, body: expect.objectContaining({ dryRun: true, users: [expect.objectContaining({ passwordHash })] }) }));
		const saved = await readFile(state.out, "utf8");
		expect(JSON.parse(saved)).toEqual(state.response());
		expect(saved).not.toContain(passwordHash); expect(saved).not.toContain("never-return");
		expect(JSON.stringify(stdout.mock.calls)).not.toMatch(/user_fixture|fixture@example|passwordHash|never-return/);
		if (process.platform !== "win32") expect((await stat(state.out)).mode & 0o777).toBe(0o600);
	});
	it("requires explicit apply and never permits file flags to enable writes", async () => {
		const state = await fixture(); await writeFile(state.input, JSON.stringify({ sourceInstance, dryRun: false, users: [user] }), { mode: 0o600 });
		const dry = vi.fn(async (_request: ToolRequest) => state.response());
		await importClerkBatch({ project, input: state.input, out: state.out, allowSensitive: true, readOnly: false, request: dry, stdout: vi.fn() });
		expect(dry.mock.calls[0]?.[0]).toMatchObject({ body: { dryRun: true } });
		const apply = vi.fn(async (_request: ToolRequest) => state.response(false));
		await importClerkBatch({ project, input: state.input, out: join(state.directory, "applied.json"), apply: true, allowSensitive: true, readOnly: false, request: apply, stdout: vi.fn() });
		expect(apply.mock.calls[0]?.[0]).toMatchObject({ body: { dryRun: false } });
	});
	it("blocks read-only and sensitive-disabled calls before reading or making a request", async () => {
		const state = await fixture(); const request = vi.fn();
		await expect(importClerkBatch({ project, input: state.input, out: state.out, apply: true, readOnly: true, allowSensitive: true, request })).rejects.toThrow(/read.only/i);
		await expect(importClerkBatch({ project, input: state.input, out: state.out, readOnly: false, allowSensitive: false, request })).rejects.toThrow(/sensitive/i);
		expect(request).not.toHaveBeenCalled();
	});
	it("refuses overwrite, unsafe permissions, symbolic input and canonical repository paths", async () => {
		const state = await fixture(); const request = vi.fn();
		await writeFile(state.out, "original", { mode: 0o600 });
		await expect(importClerkBatch({ project, input: state.input, out: state.out, readOnly: false, allowSensitive: true, request })).rejects.toThrow();
		expect(await readFile(state.out, "utf8")).toBe("original");
		const link = join(state.directory, "linked-input.json"); await symlink(state.input, link);
		await expect(importClerkBatch({ project, input: link, out: join(state.directory, "linked-result.json"), readOnly: false, allowSensitive: true, request })).rejects.toThrow();
		const unsafe = join(state.directory, "unsafe.json"); await writeFile(unsafe, "{}", { mode: 0o644 });
		if (process.platform !== "win32") await expect(importClerkBatch({ project, input: unsafe, out: join(state.directory, "unsafe-result.json"), readOnly: false, allowSensitive: true, request })).rejects.toThrow();
		const repo = join(state.directory, "repo"); await mkdir(join(repo, ".git"), { recursive: true });
		const linkedRepo = join(state.directory, "repo-link"); await symlink(repo, linkedRepo, "dir");
		await expect(importClerkBatch({ project, input: state.input, out: join(linkedRepo, "result.json"), readOnly: false, allowSensitive: true, request })).rejects.toThrow(/repository/i);
		expect(request).not.toHaveBeenCalled();
	});
	it("rejects target/source/unknown-field and stale result mismatches without echoing input or upstream errors", async () => {
		const state = await fixture(); const request = vi.fn();
		await writeFile(state.input, JSON.stringify({ project: "other-production", sourceInstance, users: [user] }));
		await expect(importClerkBatch({ project, input: state.input, out: state.out, readOnly: false, allowSensitive: true, request })).rejects.toThrow(/project/i);
		await writeFile(state.input, JSON.stringify({ sourceInstance, injected: passwordHash, users: [user] }));
		await expect(importClerkBatch({ project, input: state.input, out: state.out, readOnly: false, allowSensitive: true, request })).rejects.toThrow(/input/i);
		expect(request).not.toHaveBeenCalled();
		await writeFile(state.input, JSON.stringify({ sourceInstance, users: [user] }));
		await expect(importClerkBatch({ project, input: state.input, out: state.out, readOnly: false, allowSensitive: true, request: async () => { throw new Error(passwordHash); } })).rejects.not.toThrow(passwordHash);
		expect(await readFile(state.out, "utf8")).not.toContain(passwordHash);
		await expect(importClerkBatch({ project, input: state.input, out: join(state.directory, "stale-result.json"), readOnly: false, allowSensitive: true, request: async () => ({ ...state.response(), users: [{ ...state.response().users[0], sourceUpdatedAt: "2026-10-28T00:00:00.000Z" }] }) })).rejects.toThrow(/result/i);
	});
	it("parses a bounded strict CLI without accepting values as flags", () => {
		expect(parseImportClerkArguments(["--project", project, "--input", "/private/batch.json", "--out", "/private/result.json", "--apply"])).toMatchObject({ project, input: "/private/batch.json", out: "/private/result.json", apply: true });
		for (const args of [[], ["--project", project], ["--project", project, "--input", "--apply", "--out", "/x"], ["--project", project, "--project", project], ["--unknown", passwordHash]]) expect(() => parseImportClerkArguments(args)).toThrow();
	});
});

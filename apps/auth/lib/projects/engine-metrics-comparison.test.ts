import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const projectId = "0bda745b-b1a4-4cc9-9a1b-a55a0c0a0000";
const service = fileURLToPath(new URL("../../", import.meta.url));
const script = fileURLToPath(
	new URL("../../scripts/compare-project-engine-metrics.ts", import.meta.url),
);
const legacyStart = "2026-11-12T14:00:00Z";
const cutover = "2026-11-12T14:10:00Z";
const candidateEnd = "2026-11-12T14:20:00Z";

function metric(writer: "legacy" | "allauth") {
	const start = Date.parse(writer === "legacy" ? legacyStart : cutover);
	return {
		event: "allauth.project_engine_metrics",
		projectId,
		writer,
		transport: "hosted",
		operation: "signIn",
		windowStart: start,
		windowEnd: start + 60_000,
		outcomes: {
			ok: 3,
			redirect: 2,
			rejected: 0,
			rateLimited: 0,
			unavailable: 0,
		},
		latencyBoundsMs: [10, 25],
		latencyCounts: [3, 2, 0],
	};
}

function run(lines: unknown[], extraOptions: string[] = []) {
	const directory = mkdtempSync(join(tmpdir(), "allauth-metrics-"));
	try {
		const input = join(directory, "metrics.ndjson");
		writeFileSync(
			input,
			lines
				.map((line) => (typeof line === "string" ? line : JSON.stringify(line)))
				.join("\n"),
		);
		return spawnSync(
			process.execPath,
			[
				"--import",
				"tsx",
				script,
				input,
				"--project-id",
				projectId,
				"--legacy-start",
				legacyStart,
				"--legacy-end",
				cutover,
				"--candidate-start",
				cutover,
				"--candidate-end",
				candidateEnd,
				...extraOptions,
			],
			{ cwd: service, encoding: "utf8", timeout: 5_000 },
		);
	} finally {
		rmSync(directory, { recursive: true, force: true });
	}
}

describe("project rollout log comparison", () => {
	it("aggregates response rates and latency buckets while exposing missing transports and operations", () => {
		const legacy = metric("legacy");
		const candidate = metric("allauth");
		const result = run([
			legacy,
			{
				...legacy,
				outcomes: {
					ok: 2,
					redirect: 0,
					rejected: 1,
					rateLimited: 1,
					unavailable: 1,
				},
				latencyCounts: [2, 3, 0],
			},
			{
				...candidate,
				outcomes: {
					ok: 6,
					redirect: 1,
					rejected: 1,
					rateLimited: 1,
					unavailable: 1,
				},
				latencyCounts: [5, 4, 1],
				privateField: "synthetic-data-never-exported",
			},
			{ ...candidate, transport: "project", operation: "tokenRefresh" },
			{
				...legacy,
				event: "allauth.audit",
				privateField: "synthetic-data-never-exported",
			},
			{
				...legacy,
				projectId: "37456122-0446-4671-942d-4ce092c1d18d",
				outcomes: "synthetic-data-never-exported",
			},
		]);
		expect(result.stderr).toBe("");
		expect(result.status).toBe(0);
		expect(result.stdout).not.toContain("synthetic-data-never-exported");
		const { groups } = JSON.parse(result.stdout);
		expect(groups).toHaveLength(10);
		expect(groups[0]).toMatchObject({
			transport: "hosted",
			operation: "signIn",
			missingWriters: [],
			latencyBoundsMs: [10, 25],
			legacy: {
				requests: 10,
				outcomes: {
					ok: 5,
					redirect: 2,
					rejected: 1,
					rateLimited: 1,
					unavailable: 1,
				},
				outcomeRates: { ok: 0.5, redirect: 0.2 },
				latencyCounts: [5, 5, 0],
				latencyPercentileBuckets: {
					p50: { aboveMs: null, atMostMs: 10 },
					p95: { aboveMs: 10, atMostMs: 25 },
				},
			},
			allauth: {
				requests: 10,
				outcomeRates: { ok: 0.6, redirect: 0.1 },
				latencyPercentileBuckets: {
					p95: { aboveMs: 25, atMostMs: null },
					p99: { aboveMs: 25, atMostMs: null },
				},
			},
		});
		expect(groups[0].outcomeRateChange.ok).toBeCloseTo(0.1);
		expect(groups[0].outcomeRateChange.redirect).toBeCloseTo(-0.1);
		expect(groups).toContainEqual(
			expect.objectContaining({
				transport: "project",
				operation: "tokenRefresh",
				missingWriters: ["legacy"],
				legacy: null,
				outcomeRateChange: null,
			}),
		);
		expect(groups).toContainEqual(
			expect.objectContaining({
				transport: "hosted",
				operation: "session",
				missingWriters: ["legacy", "allauth"],
				legacy: null,
				allauth: null,
			}),
		);
	});

	it("omits windows that cross either observation interval or contain the other writer", () => {
		const start = Date.parse(cutover);
		const result = run([
			metric("legacy"),
			metric("allauth"),
			{ ...metric("legacy"), windowStart: start - 1, windowEnd: start + 1 },
			{ ...metric("allauth"), writer: "legacy" },
			{
				...metric("legacy"),
				windowStart: Date.parse(legacyStart) - 120_000,
				windowEnd: Date.parse(legacyStart) - 60_000,
			},
		]);
		expect(result.stderr).toBe("");
		const { groups, excluded } = JSON.parse(result.stdout);
		expect(excluded).toEqual({
			legacy: { partialWindows: 1, wrongWriterWindows: 0 },
			allauth: { partialWindows: 1, wrongWriterWindows: 1 },
		});
		expect(groups[0]).toMatchObject({
			legacy: { requests: 5 },
			allauth: { requests: 5 },
		});
	});

	it.each([
		{ latencyBoundsMs: [10, 50] },
		{ latencyBoundsMs: [25, 10] },
		{ latencyCounts: [4, 0, 0] },
		{ latencyCounts: [3, 2] },
		{ latencyCounts: [6, 0, -1] },
	])("fails closed on incompatible or invalid histogram fields %o", (change) => {
		const result = run([metric("legacy"), { ...metric("allauth"), ...change }]);
		expect(result.status).toBe(1);
		expect(result.stdout).toBe("");
		expect(result.stderr).toMatch(/line 2\./);
	});

	it.each([
		[["--project-id", "project-slug"], /immutable project ID/],
		[["--candidate-start", "2026-11-12T14:09:00Z"], /must not overlap/],
		[["--candidate-start", "2026-11-12T14:10:00"], /explicit UTC/],
	] as const)("rejects invalid comparison scope %o", (options, message) => {
		const result = run([], [...options]);
		expect(result.status).toBe(1);
		expect(result.stdout).toBe("");
		expect(result.stderr).toMatch(message);
	});

	it("keeps malformed log content out of diagnostics", () => {
		const result = run([metric("legacy"), "{ synthetic-private-token"]);
		expect(result.status).toBe(1);
		expect(result.stdout).toBe("");
		expect(result.stderr).toBe("Invalid NDJSON on line 2.\n");
	});
});

import { open } from "node:fs/promises";
import { parseArgs } from "node:util";
import * as z from "zod";

const immutableProjectId = /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/;
const metricEvent = "allauth.project_engine_metrics";
const writers = ["legacy", "allauth"] as const;
const transports = ["hosted", "project"] as const;
const operations = [
	"signIn",
	"callback",
	"session",
	"tokenExchange",
	"tokenRefresh",
] as const;
const outcomeKeys = [
	"ok",
	"redirect",
	"rejected",
	"rateLimited",
	"unavailable",
] as const;
const count = z.int().nonnegative();
const rowSchema = z.object({
	writer: z.enum(writers),
	transport: z.enum(transports),
	operation: z.enum(operations),
	windowStart: count,
	windowEnd: count,
	outcomes: z.strictObject({
		ok: count,
		redirect: count,
		rejected: count,
		rateLimited: count,
		unavailable: count,
	}),
	latencyBoundsMs: z.array(z.int().positive()).nonempty(),
	latencyCounts: z.array(count),
});

type Row = z.infer<typeof rowSchema>;
type Writer = Row["writer"];
type Outcomes = Row["outcomes"];
type Window = { start: number; end: number };
type Samples = { total: number; outcomes: Outcomes; latencyCounts: number[] };
type Group = { bounds: number[]; samples: Partial<Record<Writer, Samples>> };

const sum = (counts: number[]) =>
	counts.reduce((total, value) => total + value, 0);

function observationWindow(start: string | undefined, end: string | undefined) {
	const utc = z.iso.datetime();
	const from = utc.safeParse(start);
	const until = utc.safeParse(end);
	if (!from.success || !until.success)
		throw new Error("Supply an explicit UTC start and end for each writer.");
	const interval = {
		start: Date.parse(from.data),
		end: Date.parse(until.data),
	};
	if (
		!Number.isFinite(interval.start) ||
		!Number.isFinite(interval.end) ||
		interval.start >= interval.end
	)
		throw new Error("Each observation window must end after it starts.");
	return interval;
}

function projectMetric(line: string, lineNumber: number, projectId: string) {
	let input: unknown;
	try {
		input = JSON.parse(line);
	} catch {
		throw new Error(`Invalid NDJSON on line ${lineNumber}.`);
	}
	if (
		!input ||
		typeof input !== "object" ||
		!("event" in input) ||
		input.event !== metricEvent ||
		!("projectId" in input) ||
		input.projectId !== projectId
	)
		return;
	const parsed = rowSchema.safeParse(input);
	if (!parsed.success)
		throw new Error(`Invalid metric record on line ${lineNumber}.`);
	const row = parsed.data;
	const total = sum(Object.values(row.outcomes));
	if (
		row.windowStart > row.windowEnd ||
		!Number.isSafeInteger(total) ||
		row.latencyBoundsMs.some(
			(bound, index, bounds) => index > 0 && bound <= bounds[index - 1]!,
		) ||
		row.latencyCounts.length !== row.latencyBoundsMs.length + 1 ||
		sum(row.latencyCounts) !== total
	)
		throw new Error(
			`Invalid metric window or histogram on line ${lineNumber}.`,
		);
	return { row, total };
}

function addSamples(
	groups: Map<string, Group>,
	row: Row,
	total: number,
	lineNumber: number,
) {
	const key = `${row.transport}/${row.operation}`;
	let group = groups.get(key);
	if (!group) {
		group = { bounds: row.latencyBoundsMs, samples: {} };
		groups.set(key, group);
	}
	if (
		group.bounds.length !== row.latencyBoundsMs.length ||
		group.bounds.some((bound, index) => bound !== row.latencyBoundsMs[index])
	)
		throw new Error(
			`Histogram bounds differ within a comparison group on line ${lineNumber}.`,
		);
	const samples = group.samples[row.writer];
	if (!samples) {
		group.samples[row.writer] = {
			total,
			outcomes: row.outcomes,
			latencyCounts: row.latencyCounts,
		};
		return;
	}
	const combinedTotal = samples.total + total;
	if (!Number.isSafeInteger(combinedTotal))
		throw new Error(
			"Combined metric counts exceed the supported integer range.",
		);
	samples.total = combinedTotal;
	for (const key of outcomeKeys) samples.outcomes[key] += row.outcomes[key];
	for (const [index, value] of row.latencyCounts.entries())
		samples.latencyCounts[index]! += value;
}

function percentileBucket(
	samples: Samples,
	bounds: number[],
	percentile: number,
) {
	const rank = Math.ceil(samples.total * percentile);
	let cumulative = 0;
	for (const [index, count] of samples.latencyCounts.entries()) {
		cumulative += count;
		if (cumulative >= rank)
			return {
				aboveMs: bounds[index - 1] ?? null,
				atMostMs: bounds[index] ?? null,
			};
	}
	throw new Error("Combined metric counts do not match the histogram.");
}

function summarize(samples: Samples | undefined, bounds: number[]) {
	if (!samples) return null;
	const { total, outcomes, latencyCounts } = samples;
	return {
		requests: total,
		outcomes,
		outcomeRates: total
			? Object.fromEntries(
					outcomeKeys.map((key) => [key, outcomes[key] / total]),
				)
			: null,
		latencyCounts,
		latencyPercentileBuckets: total
			? {
					p50: percentileBucket(samples, bounds, 0.5),
					p95: percentileBucket(samples, bounds, 0.95),
					p99: percentileBucket(samples, bounds, 0.99),
				}
			: null,
	};
}

async function compare(
	lines: AsyncIterable<string>,
	projectId: string,
	windows: Record<Writer, Window>,
) {
	const groups = new Map<string, Group>();
	const excluded = {
		legacy: { partialWindows: 0, wrongWriterWindows: 0 },
		allauth: { partialWindows: 0, wrongWriterWindows: 0 },
	};
	let lineNumber = 0;
	for await (const line of lines) {
		lineNumber++;
		if (!line.trim()) continue;
		const metric = projectMetric(line, lineNumber, projectId);
		if (!metric) continue;
		const { row, total } = metric;
		for (const writer of writers) {
			const { start, end } = windows[writer];
			if (
				row.windowStart >= start &&
				row.windowStart < end &&
				row.windowEnd <= end
			) {
				if (row.writer === writer) addSamples(groups, row, total, lineNumber);
				else excluded[writer].wrongWriterWindows++;
			} else if (row.windowStart < end && row.windowEnd > start) {
				excluded[writer].partialWindows++;
			}
		}
	}
	return {
		projectId,
		windows: Object.fromEntries(
			writers.map((writer) => {
				const { start, end } = windows[writer];
				return [
					writer,
					{
						start: new Date(start).toISOString(),
						end: new Date(end).toISOString(),
					},
				];
			}),
		),
		excluded,
		groups: transports.flatMap((transport) =>
			operations.map((operation) => {
				const group = groups.get(`${transport}/${operation}`);
				const bounds = group?.bounds ?? [];
				const legacy = summarize(group?.samples.legacy, bounds);
				const allauth = summarize(group?.samples.allauth, bounds);
				const legacyRates = legacy?.outcomeRates;
				const allauthRates = allauth?.outcomeRates;
				return {
					transport,
					operation,
					missingWriters: writers.filter(
						(writer) => !group?.samples[writer]?.total,
					),
					latencyBoundsMs: group?.bounds ?? null,
					legacy,
					allauth,
					outcomeRateChange:
						legacyRates && allauthRates
							? Object.fromEntries(
									outcomeKeys.map((key) => [
										key,
										allauthRates[key]! - legacyRates[key]!,
									]),
								)
							: null,
				};
			}),
		),
	};
}

async function main() {
	const { values, positionals } = parseArgs({
		allowPositionals: true,
		options: {
			"project-id": { type: "string" },
			"legacy-start": { type: "string" },
			"legacy-end": { type: "string" },
			"candidate-start": { type: "string" },
			"candidate-end": { type: "string" },
		},
	});
	const projectId = values["project-id"];
	if (
		!projectId ||
		!immutableProjectId.test(projectId) ||
		positionals.length !== 1
	)
		throw new Error(
			"Supply one NDJSON file and an exact immutable project ID.",
		);
	const legacy = observationWindow(
		values["legacy-start"],
		values["legacy-end"],
	);
	const allauth = observationWindow(
		values["candidate-start"],
		values["candidate-end"],
	);
	if (legacy.start < allauth.end && allauth.start < legacy.end)
		throw new Error(
			"Legacy and candidate observation windows must not overlap.",
		);
	const file = await open(positionals[0]!, "r");
	try {
		const result = await compare(file.readLines(), projectId, {
			legacy,
			allauth,
		});
		console.log(JSON.stringify(result, null, 2));
	} finally {
		await file.close();
	}
}

try {
	await main();
} catch (error) {
	console.error(
		error instanceof Error ? error.message : "Metric comparison failed.",
	);
	process.exitCode = 1;
}

import type { AuthEngine } from "../auth-engine";
import type { AuthEnvironment } from "../configuration";
import { setting } from "../configuration";

const uuid = /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/;
const windowMs = 60_000;
const latencyBoundsMs = [10, 25, 50, 100, 250, 500, 1000, 2500, 5000];
const maximumGrantBody = 8192;
const signIn = new Set([
	"/sign-in/email",
	"/sign-in/username",
	"/sign-in/email-otp",
	"/sign-in/anonymous",
	"/passkey/verify-authentication",
	"/siwe/verify",
	"/two-factor/verify-totp",
	"/two-factor/verify-backup-code",
]);
const callback =
	/^\/(?:callback\/[^/]+|sso\/(?:callback|saml2\/sp\/acs|saml2\/callback)\/[^/]+|magic-link\/verify)$/;
type Outcome = "ok" | "redirect" | "rejected" | "rateLimited" | "unavailable";
type Operation =
	| "signIn"
	| "callback"
	| "session"
	| "tokenExchange"
	| "tokenRefresh"
	| "providerAccessToken"
	| "providerTokenRefresh";
type Series = {
	projectId: string;
	writer: "legacy" | "allauth";
	transport: "hosted" | "project";
	operation: Operation;
};
type Counts = Record<Outcome, number>;
type Bucket = {
	series: Series;
	counts: Counts;
	latency: number[];
};

export const projectEngineMetricsSetting = "ALLAUTH_PROJECT_ENGINE_METRICS_IDS";

export function projectEngineMetricsSelected(
	env: AuthEnvironment,
	projectId: string,
) {
	const value = setting(env, projectEngineMetricsSetting).trim();
	if (!value || !uuid.test(projectId)) return false;
	const ids = value.split(",").map((id) => id.trim());
	return ids.every((id) => uuid.test(id)) && ids.includes(projectId);
}

function operationFor(
	request: Request,
	basePath: string,
): Operation | undefined {
	const path = new URL(request.url).pathname;
	if (!path.startsWith(`${basePath}/`)) return;
	const suffix = path.slice(basePath.length);
	if (request.method === "POST") {
		if (suffix === "/oauth2/token") return "tokenExchange";
		if (suffix === "/get-access-token") return "providerAccessToken";
		if (suffix === "/refresh-token") return "providerTokenRefresh";
		if (signIn.has(suffix)) return "signIn";
	}
	if (request.method === "GET" && suffix === "/get-session") return "session";
	if (
		(request.method === "GET" || request.method === "POST") &&
		callback.test(suffix)
	)
		return "callback";
}

async function isRefresh(request: Request) {
	let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
	try {
		const contentType = request.headers
			.get("content-type")
			?.split(";")[0]
			?.trim();
		if (
			contentType !== "application/x-www-form-urlencoded" &&
			contentType !== "application/json"
		)
			return false;
		reader = request.clone().body?.getReader();
		if (!reader) return false;
		const decoder = new TextDecoder();
		let body = "";
		let size = 0;
		for (;;) {
			const item = await reader.read();
			if (item.done) break;
			size += item.value.byteLength;
			if (size > maximumGrantBody) {
				void reader.cancel().catch(() => {});
				return false;
			}
			body += decoder.decode(item.value, { stream: true });
		}
		body += decoder.decode();
		if (contentType === "application/x-www-form-urlencoded")
			return new URLSearchParams(body).get("grant_type") === "refresh_token";
		const value: unknown = JSON.parse(body);
		return Boolean(
			value &&
				typeof value === "object" &&
				"grant_type" in value &&
				value.grant_type === "refresh_token",
		);
	} catch {
		return false;
	} finally {
		reader?.releaseLock();
	}
}

function outcomeFor(response: Response): Outcome {
	if (response.status >= 500) return "unavailable";
	if (response.status === 429) return "rateLimited";
	if (response.status >= 400) return "rejected";
	if (response.status >= 300) {
		try {
			const location = new URL(
				response.headers.get("location") ?? "",
				"https://allauth.invalid",
			);
			if (
				location.pathname === "/auth-error" ||
				location.searchParams.has("error")
			)
				return "rejected";
		} catch {
			// A malformed redirect still has a redirect status.
		}
		return "redirect";
	}
	return "ok";
}

export function createProjectEngineMetrics(
	report: (value: object) => void = (value) =>
		console.info(JSON.stringify(value)),
) {
	let windowStart = 0;
	let timer: ReturnType<typeof setTimeout> | undefined;
	const buckets = new Map<string, Bucket>();

	function flush() {
		if (timer) clearTimeout(timer);
		timer = undefined;
		const end = Date.now();
		const completed = Array.from(buckets.values());
		buckets.clear();
		for (const bucket of completed) {
			try {
				report({
					event: "allauth.project_engine_metrics",
					windowStart,
					windowEnd: end,
					...bucket.series,
					outcomes: bucket.counts,
					latencyBoundsMs,
					latencyCounts: bucket.latency,
				});
			} catch {
				// Observability cannot interrupt authentication.
			}
		}
	}

	function record(series: Series, outcome: Outcome, durationMs: number) {
		const key = JSON.stringify(series);
		let bucket = buckets.get(key);
		if (!bucket) {
			bucket = {
				series,
				counts: {
					ok: 0,
					redirect: 0,
					rejected: 0,
					rateLimited: 0,
					unavailable: 0,
				},
				latency: Array<number>(latencyBoundsMs.length + 1).fill(0),
			};
			buckets.set(key, bucket);
		}
		bucket.counts[outcome]++;
		const index = latencyBoundsMs.findIndex((bound) => durationMs <= bound);
		bucket.latency[index === -1 ? latencyBoundsMs.length : index]!++;
		if (!timer) {
			windowStart = Date.now();
			timer = setTimeout(flush, windowMs);
			timer.unref?.();
		}
	}

	return { record, flush };
}

const projectMetrics = createProjectEngineMetrics();

/** Aggregate fixed operation groups after trusted routing selects a project. */
export function observeProjectEngine(
	engine: AuthEngine,
	options: Omit<Series, "operation"> & {
		basePath: string;
		metrics?: ReturnType<typeof createProjectEngineMetrics>;
	},
): AuthEngine {
	const { basePath, metrics = projectMetrics, ...series } = options;

	function observe(handler: (request: Request) => Promise<Response>) {
		return async (request: Request) => {
			const operation = operationFor(request, basePath);
			if (!operation) return handler(request);
			const refresh = operation === "tokenExchange" ? isRefresh(request) : null;
			const started = performance.now();
			const record = (outcome: Outcome) => {
				const duration = performance.now() - started;
				if (refresh !== null) {
					void refresh
						.then((isTokenRefresh) =>
							metrics.record(
								{
									...series,
									operation: isTokenRefresh ? "tokenRefresh" : operation,
								},
								outcome,
								duration,
							),
						)
						.catch(() => {});
				} else {
					try {
						metrics.record({ ...series, operation }, outcome, duration);
					} catch {
						// Observability cannot interrupt authentication.
					}
				}
			};
			try {
				const response = await handler(request);
				record(outcomeFor(response));
				return response;
			} catch (error) {
				record("unavailable");
				throw error;
			}
		};
	}

	return {
		...engine,
		dispatch: observe((request) => engine.dispatch(request)),
		readSession: observe((request) => engine.readSession(request)),
	};
}

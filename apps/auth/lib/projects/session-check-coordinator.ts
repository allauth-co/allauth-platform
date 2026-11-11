import { APIError } from "better-auth";
import type { SessionCheckAdmission } from "./session-introspection-admission";

interface Snapshot {
	body: Uint8Array | null;
	status: number;
	statusText: string;
	headers: Headers;
}
interface Options {
	maxPending?: number;
	maxCohorts?: number;
	maxPerKey?: number;
	timeoutMs?: number;
}
export interface SessionCheckCoordinator {
	check: (
		key: string,
		consume: () => Promise<SessionCheckAdmission>,
		session: () => Promise<Response>,
	) => Promise<Response>;
}

/** Stable service errors contain no credentials or provider exception messages. */
export function sessionCheckRefusal(
	status: 429 | 503,
	retryAfter = 1,
): Response {
	return Response.json(
		{
			error:
				status === 429
					? "Session checks are temporarily rate limited."
					: "Session checks are temporarily unavailable.",
			code:
				status === 429
					? "ALLAUTH_SESSION_CHECK_RATE_LIMITED"
					: "ALLAUTH_SESSION_CHECK_UNAVAILABLE",
		},
		{
			status,
			headers: {
				"Cache-Control": "no-store",
				Pragma: "no-cache",
				...(status === 429
					? { "Retry-After": String(Math.max(1, Math.ceil(retryAfter))) }
					: {}),
			},
		},
	);
}

function response(snapshot: Snapshot): Response {
	const headers = new Headers(snapshot.headers);
	// Preserve separate cookie fields, including Expires dates containing commas.
	headers.delete("set-cookie");
	for (const cookie of snapshot.headers.getSetCookie())
		headers.append("set-cookie", cookie);
	return new Response(snapshot.body?.slice() ?? null, {
		status: snapshot.status,
		statusText: snapshot.statusText,
		headers,
	});
}

async function snapshot(value: Response): Promise<Snapshot> {
	const reader = value.body?.getReader();
	const chunks: Uint8Array[] = [];
	let length = 0;
	if (reader) {
		try {
			while (true) {
				const part = await reader.read();
				if (part.done) break;
				length += part.value.byteLength;
				if (length > 1024 * 1024) {
					void reader.cancel().catch(() => {});
					throw new Error(
						"Session response exceeds the bounded transport size.",
					);
				}
				chunks.push(part.value);
			}
		} finally {
			reader.releaseLock();
		}
	}
	const body = value.body ? new Uint8Array(length) : null;
	let offset = 0;
	for (const chunk of chunks) {
		body!.set(chunk, offset);
		offset += chunk.byteLength;
	}
	const headers = new Headers(value.headers);
	headers.set("Cache-Control", "no-store");
	headers.set("Pragma", "no-cache");
	return { body, status: value.status, statusText: value.statusText, headers };
}

function normalizedFailure(value: Response): Response {
	if (value.status !== 429 && value.status < 500) return value;
	void value.body?.cancel().catch(() => {});
	const failure = sessionCheckRefusal(
		value.status === 429 ? 429 : 503,
		Number(value.headers.get("retry-after")) || 1,
	);
	for (const cookie of value.headers.getSetCookie())
		failure.headers.append("set-cookie", cookie);
	if (value.status === 429 && value.headers.has("retry-after"))
		failure.headers.set("retry-after", value.headers.get("retry-after")!);
	return failure;
}

/**
 * Combines admission-overlapping calls only. The join gate closes BEFORE the
 * authoritative read starts, so new arrivals never attach to an older read.
 * Completed results are never indexed. Each caller consumes shared admission.
 * Timed-out underlying work retains capacity until it actually settles.
 */
export function createSessionCheckCoordinator(
	options: Options = {},
): SessionCheckCoordinator {
	const {
		maxPending = 1024,
		maxCohorts = 128,
		maxPerKey = 120,
		timeoutMs = 10_000,
	} = options;
	if (
		![maxPending, maxCohorts, maxPerKey, timeoutMs].every(
			(value) => Number.isSafeInteger(value) && value > 0,
		)
	)
		throw new Error("Invalid session-check coordination bounds.");
	type Cohort = {
		result: Promise<Snapshot>;
		resolve: (value: Snapshot) => void;
		expiration: Promise<Snapshot>;
		expire: (value: Snapshot) => void;
		timer: ReturnType<typeof setTimeout>;
		admissions: number;
		started: boolean;
		expired: boolean;
		reading: boolean;
		released: boolean;
	};
	const joining = new Map<string, Cohort>();
	const perKey = new Map<string, number>();
	let pending = 0,
		cohorts = 0;
	const unavailable = () => snapshot(sessionCheckRefusal(503));

	return {
		async check(key, consume, session) {
			if (pending >= maxPending || (perKey.get(key) ?? 0) >= maxPerKey)
				return sessionCheckRefusal(429);
			let selected = joining.get(key);
			if (!selected) {
				if (cohorts >= maxCohorts) return sessionCheckRefusal(429);
				let resolve!: Cohort["resolve"], expire!: Cohort["expire"];
				const result = new Promise<Snapshot>((done) => {
					resolve = done;
				});
				const expiration = new Promise<Snapshot>((done) => {
					expire = done;
				});
				const cohort: Cohort = {
					result,
					resolve,
					expiration,
					expire,
					admissions: 0,
					started: false,
					expired: false,
					reading: false,
					released: false,
					timer: setTimeout(() => {
						cohort.expired = true;
						if (joining.get(key) === cohort) joining.delete(key);
						void unavailable().then((value) => {
							cohort.resolve(value);
							cohort.expire(value);
						});
					}, timeoutMs),
				};
				joining.set(key, cohort);
				selected = cohort;
				cohorts++;
			}
			const cohort = selected;
			pending++;
			perKey.set(key, (perKey.get(key) ?? 0) + 1);
			cohort.admissions++;
			const finish = () => {
				if (cohort.admissions || cohort.reading || cohort.released) return;
				cohort.released = true;
				if (joining.get(key) === cohort) joining.delete(key);
				clearTimeout(cohort.timer);
				cohorts--;
			};
			const operation = (async () => {
				let admission: SessionCheckAdmission;
				try {
					admission = await consume();
				} catch {
					return await unavailable();
				} finally {
					cohort.admissions--;
				}
				if (cohort.expired) return await unavailable();
				if (!admission.allowed)
					return await snapshot(sessionCheckRefusal(429, admission.retryAfter));
				if (!cohort.started) {
					cohort.started = true;
					// No caller arriving after this point can reuse this authority read.
					if (joining.get(key) === cohort) joining.delete(key);
					cohort.reading = true;
					void (async () => {
						try {
							cohort.resolve(
								await snapshot(normalizedFailure(await session())),
							);
						} catch (error) {
							try {
								const failure =
									error instanceof APIError && error.statusCode < 500
										? normalizedFailure(
												Response.json(
													error.body ?? {
														error: "Session check rejected.",
														code: "ALLAUTH_SESSION_CHECK_REJECTED",
													},
													{ status: error.statusCode, headers: error.headers },
												),
											)
										: sessionCheckRefusal(503);
								cohort.resolve(await snapshot(failure));
							} catch {
								cohort.resolve(await unavailable());
							}
						} finally {
							cohort.reading = false;
							finish();
						}
					})();
				}
				return await cohort.result;
			})().finally(() => {
				pending--;
				const left = perKey.get(key)! - 1;
				if (left) perKey.set(key, left);
				else perKey.delete(key);
				finish();
			});
			return response(await Promise.race([operation, cohort.expiration]));
		},
	};
}

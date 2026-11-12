import { useSyncExternalStore } from "react";

/** A safe, public error returned by the app's AllAuth proxy. */
export type AllAuthClientError = {
	code?: string;
	message: string;
	status: number;
	statusText: string;
	retryAfter?: string;
};

export type ClientResult<T> =
	| { data: T | null; error: null }
	| { data: null; error: AllAuthClientError };

export type ClientQuery = Readonly<
	Record<string, string | number | boolean | undefined>
>;

export type ClientQueryOptions<Q = ClientQuery> = {
	query?: Q;
	headers?: HeadersInit;
	signal?: AbortSignal;
};

type QueryState<T, Q> = {
	data: T | null;
	error: AllAuthClientError | null;
	isPending: boolean;
	isRefetching: boolean;
	refetch: (options?: { query?: Q }) => Promise<void>;
};

export function createClientQuery<T, Q extends ClientQuery = ClientQuery>(
	load: (options?: ClientQueryOptions<Q>) => Promise<ClientResult<T>>,
	onChange?: (previous: T | null, current: T | null) => void,
	onMount?: (refresh: () => void) => () => void,
) {
	const listeners = new Set<() => void>();
	let active:
		| { controller: AbortController; promise: Promise<void> }
		| undefined;
	let dirty = true;
	let updatedAt = 0;
	let cleanup: (() => void) | undefined;

	function publish(state: QueryState<T, Q>) {
		snapshot = state;
		for (const listener of listeners) listener();
	}

	function refetch(options?: { query?: Q }): Promise<void> {
		if (active && !options?.query) return active.promise;
		active?.controller.abort();
		dirty = false;
		const controller = new AbortController();
		const promise = Promise.resolve()
			.then(async () => {
				if (controller.signal.aborted) return;
				const result = await load({
					query: options?.query,
					signal: controller.signal,
				});
				if (controller.signal.aborted) return;
				const previous = snapshot.data;
				const data =
					result.error && result.error.status !== 401 ? previous : result.data;
				updatedAt = Date.now();
				publish({
					data,
					error: result.error,
					isPending: false,
					isRefetching: false,
					refetch,
				});
				if (previous !== data) onChange?.(previous, data);
			})
			.finally(() => {
				if (active?.controller === controller) active = undefined;
			});
		active = { controller, promise };
		publish({
			...snapshot,
			error: null,
			isPending: snapshot.data === null,
			isRefetching: true,
		});
		return promise;
	}

	const initial: QueryState<T, Q> = {
		data: null,
		error: null,
		isPending: true,
		isRefetching: false,
		refetch,
	};
	let snapshot = initial;
	const read = () => snapshot;
	const readServer = () => initial;

	function subscribe(listener: () => void) {
		listeners.add(listener);
		if (listeners.size === 1) {
			if (dirty || Date.now() - updatedAt >= 1_000) void refetch();
			cleanup = onMount?.(() => {
				if (Date.now() - updatedAt >= 5_000 && !active) void refetch();
			});
		}
		return () => {
			listeners.delete(listener);
			if (listeners.size === 0) {
				cleanup?.();
				cleanup = undefined;
			}
		};
	}

	function invalidate(clear = false) {
		active?.controller.abort();
		active = undefined;
		dirty = true;
		if (clear) publish(initial);
		if (listeners.size) void refetch();
	}

	return {
		invalidate,
		useQuery: () => useSyncExternalStore(subscribe, read, readServer),
	};
}

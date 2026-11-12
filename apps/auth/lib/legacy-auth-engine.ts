import { runWithAdapter } from "@better-auth/core/context";
import type { AuthInstance } from "./api";
import type { AuthEngine } from "./auth-engine";

type LegacyInstance = Pick<AuthInstance, "$context" | "handler"> & {
	api: Pick<
		AuthInstance["api"],
		"getSession" | "accountSessions" | "accountRevokeSession"
	>;
};

const engines = new WeakMap<LegacyInstance, AuthEngine>();

/** Bind to the exact native instance and adapter selected for this request. */
export function legacyAuthEngine(instance: LegacyInstance): AuthEngine {
	const existing = engines.get(instance);
	if (existing) return existing;

	async function withAdapter<T>(operation: () => Promise<T>): Promise<T> {
		return runWithAdapter((await instance.$context).adapter, operation);
	}

	const engine: AuthEngine = {
		dispatch: (request) => instance.handler(request),
		readPrincipal: (headers) =>
			withAdapter(async () => {
				const current = await instance.api.getSession({
					headers,
					query: { disableCookieCache: true },
				});
				if (!current) return null;
				const { session, user } = current;
				return {
					session: {
						id: session.id,
						userId: session.userId,
						impersonatedBy: session.impersonatedBy ?? undefined,
					},
					user: {
						id: user.id,
						name: user.name,
						email: user.email,
						emailVerified: user.emailVerified,
						role: user.role ?? undefined,
						banned: user.banned ?? undefined,
					},
				};
			}),
		readSession: (request) =>
			withAdapter(() =>
				instance.api.getSession({
					headers: request.headers,
					request,
					query: { disableCookieCache: true },
					asResponse: true,
				}),
			),
		listAccountSessions: (headers) =>
			instance.api.accountSessions({ headers, asResponse: true }),
		revokeAccountSession: (headers, body) =>
			instance.api.accountRevokeSession({ headers, body, asResponse: true }),
		readDirectory: (operation, headers, query) =>
			withAdapter(async () => {
				const endpoint: unknown = Reflect.get(instance.api, operation);
				if (typeof endpoint !== "function")
					throw new Error("Directory endpoint is unavailable.");
				return Reflect.apply(endpoint, instance.api, [
					{ headers, query, asResponse: true },
				]) as Promise<Response>;
			}),
	};
	// The admission coordinator uses this identity to distinguish policy revisions.
	engines.set(instance, engine);
	return engine;
}

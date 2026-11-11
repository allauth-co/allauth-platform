import {
	authMutationKeys,
	authQueryKeys,
	localization,
} from "@better-auth-ui/core";
import { passkeyMutationKeys } from "@better-auth-ui/core/plugins/passkey";
import { MutationCache, QueryClient } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ErrorToaster } from "@/components/better-auth-ui/error-toaster";

const state = vi.hoisted(() => ({
	client: undefined as QueryClient | undefined,
	cleanup: undefined as (() => void) | void,
	toast: vi.fn(),
	previousError: vi.fn(),
}));
vi.mock("react", async () => ({
	...(await vi.importActual<typeof import("react")>("react")),
	useEffect: (effect: () => (() => void) | void) => {
		state.cleanup = effect();
	},
}));
vi.mock("@tanstack/react-query", async () => ({
	...(await vi.importActual<typeof import("@tanstack/react-query")>(
		"@tanstack/react-query",
	)),
	useQueryClient: () => state.client,
}));
vi.mock("@/components/better-auth-ui/lib/use-auth", async () => {
	const { localization: nativeLocalization } = await import(
		"@better-auth-ui/core"
	);
	return { useAuth: () => ({ localization: nativeLocalization }) };
});
vi.mock("sonner", () => ({ toast: { error: state.toast } }));

beforeEach(() => {
	state.toast.mockReset();
	state.previousError.mockReset();
	state.client = new QueryClient({
		mutationCache: new MutationCache({ onError: state.previousError }),
		defaultOptions: { mutations: { retry: false }, queries: { retry: false } },
	});
	vi.spyOn(console, "error").mockImplementation(() => undefined);
	ErrorToaster();
});
afterEach(() => {
	state.cleanup?.();
	state.client?.clear();
	vi.restoreAllMocks();
});

async function failMutation(
	error: unknown,
	mutationKey: readonly unknown[] = passkeyMutationKeys.signIn,
	meta?: { errorPresentation: "silent" | "inline" | "toast" },
) {
	const client = state.client!;
	const mutation = client.getMutationCache().build(client, {
		mutationKey,
		meta,
		mutationFn: async () => {
			throw error;
		},
	});
	await expect(mutation.execute(undefined)).rejects.toBe(error);
}

describe("native passkey error presentation", () => {
	/** @see packages/passkey/src/client.ts */
	it.each([
		{ code: "AUTH_CANCELLED", message: "Auth cancelled", status: 400 },
		{
			code: "ERROR_PASSTHROUGH_SEE_CAUSE_PROPERTY",
			message: "Auth cancelled",
			status: 400,
		},
		{ code: "ERROR_CEREMONY_ABORTED", message: "Auth cancelled", status: 400 },
		new DOMException("The request was cancelled.", "NotAllowedError"),
		new Error("WebAuthn failed", {
			cause: new DOMException("Aborted", "AbortError"),
		}),
	])("toasts an expected native ceremony failure without triggering the Next console overlay: %o", async (error) => {
		await failMutation(error);
		expect(state.toast).toHaveBeenCalledOnce();
		expect(state.toast).toHaveBeenCalledWith(localization.errors.passkeyFailed);
		expect(console.error).not.toHaveBeenCalled();
		expect(state.previousError).toHaveBeenCalledOnce();
	});

	it.each([
		{ code: "ERROR_INVALID_RP_ID", status: 400 },
		{ code: "AUTH_CANCELLED", status: 500 },
		{ code: "INTERNAL_SERVER_ERROR", status: 500 },
		new TypeError("Failed to fetch"),
	])("keeps unexpected passkey configuration/server failures visible: %o", async (error) => {
		await failMutation(error);
		expect(state.toast).toHaveBeenCalledWith(localization.errors.passkeyFailed);
		expect(console.error).toHaveBeenCalledWith("[Better Auth UI]", error);
	});

	it("keeps the native silent autofill cancellation contract", async () => {
		await failMutation(
			{ code: "AUTH_CANCELLED", status: 400 },
			passkeyMutationKeys.autoFill,
			{ errorPresentation: "silent" },
		);
		expect(state.toast).not.toHaveBeenCalled();
		expect(console.error).not.toHaveBeenCalled();
	});

	it.each([
		[401, localization.errors.sessionExpired],
		[403, localization.errors.permissionDenied],
		[429, localization.errors.rateLimited],
	] as const)("keeps actionable HTTP %s errors even if a wrapper carries a cancellation code", async (status, message) => {
		const error = { code: "AUTH_CANCELLED", status };
		await failMutation(error);
		expect(state.toast).toHaveBeenCalledWith(message);
		expect(console.error).toHaveBeenCalledWith("[Better Auth UI]", error);
	});

	it("retains unrelated actionable authentication and query error reporting", async () => {
		const error = { code: "INVALID_EMAIL_OR_PASSWORD", status: 401 };
		await failMutation(error, authMutationKeys.signIn.email);
		expect(state.toast).toHaveBeenCalledWith(
			localization.errors.invalidCredentials,
		);
		expect(console.error).toHaveBeenCalledWith("[Better Auth UI]", error);
		const queryError = { code: "INTERNAL_SERVER_ERROR", status: 500 };
		const client = state.client!;
		const query = client.getQueryCache().build(client, {
			queryKey: authQueryKeys.session,
			queryFn: async () => {
				throw queryError;
			},
		});
		await expect(query.fetch()).rejects.toBe(queryError);
		expect(state.toast).toHaveBeenCalledWith(localization.errors.generic);
		expect(console.error).toHaveBeenCalledWith("[Better Auth UI]", queryError);
	});

	it("never treats a cancellation code from another sign-in method as a passkey ceremony", async () => {
		const error = { code: "AUTH_CANCELLED", status: 400 };
		await failMutation(error, authMutationKeys.signIn.social);
		expect(state.toast).toHaveBeenCalledWith(localization.errors.generic);
		expect(console.error).toHaveBeenCalledWith("[Better Auth UI]", error);
	});
});

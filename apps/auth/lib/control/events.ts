import type { GenericEndpointContext } from "@better-auth/core";
import { getCurrentAdapter } from "@better-auth/core/context";
import type { DBTransactionAdapter } from "@better-auth/core/db/adapter";
import { APIError } from "better-auth";
import {
	controlEventAttributes,
	sanitizeControlMetadata,
} from "./event-metadata";
import {
	controlFailureCode,
	controlResponseFailure as browserResponseFailure,
} from "./event-contract";
import type { ControlEventInput } from "./types";

export {
	isPrimaryAuthenticationPath,
	mutationEventType,
	publicControlEvent,
} from "./event-contract";
export { sanitizeControlMetadata } from "./event-metadata";

/** Persist an immutable event through Better Auth's current transaction adapter. */
export async function writeControlEvent(
	adapter: Pick<DBTransactionAdapter, "create">,
	event: ControlEventInput,
): Promise<void> {
	const data: Record<string, unknown> = {
		type: event.type.slice(0, 128),
		outcome: event.outcome,
		createdAt: event.createdAt || new Date(),
		metadata: sanitizeControlMetadata(event.metadata),
	};
	Object.assign(data, controlEventAttributes(event));
	if (event.id) data.id = event.id;
	// Database hooks can run before a parent transaction commits. Reuse its adapter so
	// audit rows are atomic with the mutation and never wait on their own transaction.
	const current = await getCurrentAdapter(adapter as DBTransactionAdapter);
	await current.create({
		model: "allauthEvent",
		data,
		...(event.id ? { forceAllowId: true } : {}),
	});
}

/** Add safe request context without serializing headers, bodies or authentication responses. */
export async function recordControlEvent(
	ctx: GenericEndpointContext,
	event: ControlEventInput,
	ipHeader?: string,
): Promise<void> {
	const headers = ctx.headers || ctx.request?.headers;
	await writeControlEvent(ctx.context.adapter, {
		...event,
		ipAddress:
			event.ipAddress ||
			(ipHeader ? headers?.get(ipHeader) || undefined : undefined),
		userAgent: event.userAgent || headers?.get("user-agent") || undefined,
	});
}

/** Interpret genuine errors returned by the legacy adapter within the browser result precedence. */
export function controlResponseFailure(returned: unknown, headers?: Headers) {
	return browserResponseFailure(returned, headers, (error) => {
		if (!(error instanceof APIError)) return;
		if (error.statusCode >= 300 && error.statusCode < 400)
			return { failed: false, pendingMFA: false };
		return {
			failed: true,
			code: controlFailureCode(error.body?.code),
			pendingMFA: false,
		};
	});
}

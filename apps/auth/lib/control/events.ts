import type { GenericEndpointContext } from "@better-auth/core";
import { getCurrentAdapter } from "@better-auth/core/context";
import type { DBTransactionAdapter } from "@better-auth/core/db/adapter";
import { APIError } from "better-auth";
import type { ControlEvent, ControlEventInput } from "./types";

const metadataFields = new Set([
	"path",
	"method",
	"provider",
	"errorCode",
	"reason",
	"status",
	"fields",
	"sessionId",
	"newDevice",
	"knownDevice",
	"riskScore",
	"signal",
	"ruleId",
	"ruleType",
	"policy",
	"monitor",
	"legacy",
	"version",
	"action",
	"count",
	"windowSeconds",
	"blockedUntil",
	"expiresAt",
	"applicationAuditId",
	"actorKind",
	"contextKind",
	"contextId",
]);
const credentialKey =
	/password|secret|token|cookie|authorization|credential|otp|backup.?code|private.?metadata|access.?key|email|address/i;

/** Drop unknown and credential-bearing metadata, and bound strings/arrays before storage. */
export function sanitizeControlMetadata(
	metadata: Record<string, unknown> | undefined,
): Record<string, unknown> {
	const result: Record<string, unknown> = {};
	for (const [key, value] of Object.entries(metadata || {}).slice(0, 32)) {
		if (!metadataFields.has(key) || credentialKey.test(key)) continue;
		if (typeof value === "string")
			result[key] = value.slice(0, 256).replace(/[\u0000-\u001f]/g, "");
		else if (
			typeof value === "boolean" ||
			(typeof value === "number" && Number.isFinite(value)) ||
			value === null
		)
			result[key] = value;
		else if (Array.isArray(value))
			result[key] = value
				.filter(
					(item): item is string =>
						typeof item === "string" && !credentialKey.test(item),
				)
				.slice(0, 20)
				.map((item) => item.slice(0, 80));
	}
	return result;
}

const optionalString = (value: unknown, length: number) =>
	typeof value === "string" && value
		? value.slice(0, length).replace(/[\u0000-\u001f]/g, "")
		: undefined;

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
	for (const field of [
		"actorId",
		"userId",
		"organizationId",
		"clientId",
		"targetId",
		"ipAddress",
		"userAgent",
	] as const) {
		const value = optionalString(
			event[field],
			field === "userAgent" ? 512 : 160,
		);
		if (value) data[field] = value;
	}
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

/** Explicit response projection prevents future database additions from leaking through audit APIs. */
export function publicControlEvent(
	event: Record<string, unknown>,
): ControlEvent {
	const result: ControlEvent = {
		id: String(event.id),
		type: String(event.type),
		outcome:
			event.outcome === "failure" || event.outcome === "blocked"
				? event.outcome
				: "success",
		createdAt: new Date(event.createdAt as Date | string).toISOString(),
		metadata: sanitizeControlMetadata(
			typeof event.metadata === "object" &&
				event.metadata &&
				!Array.isArray(event.metadata)
				? (event.metadata as Record<string, unknown>)
				: undefined,
		),
	};
	for (const field of [
		"actorId",
		"userId",
		"organizationId",
		"clientId",
		"targetId",
		"ipAddress",
		"userAgent",
	] as const) {
		const value = optionalString(
			event[field],
			field === "userAgent" ? 512 : 160,
		);
		if (value) result[field] = value;
	}
	return result;
}

/** HTTP redirects with protocol errors are failures, while MFA redirects remain pending. */
export function controlResponseFailure(
	returned: unknown,
	headers?: Headers,
): { failed: boolean; code?: string; pendingMFA: boolean } {
	const record =
		returned && typeof returned === "object"
			? (returned as Record<string, unknown>)
			: undefined;
	if (record?.twoFactorRedirect === true)
		return { failed: false, pendingMFA: true };
	const location =
		headers?.get("location") ||
		(typeof record?.url === "string" ? record.url : undefined);
	if (location) {
		try {
			const url = new URL(location, "https://allauth.invalid");
			if (url.pathname === "/two-factor")
				return { failed: false, pendingMFA: true };
			const error = url.searchParams.get("error");
			if (error)
				return {
					failed: true,
					code: /^[a-zA-Z0-9_-]{1,100}$/.test(error)
						? error
						: "AUTHENTICATION_FAILED",
					pendingMFA: false,
				};
		} catch {
			/* Malformed destinations are never serialized. */
		}
	}
	if (returned instanceof APIError) {
		if (returned.statusCode >= 300 && returned.statusCode < 400)
			return { failed: false, pendingMFA: false };
		const error = returned.body?.code;
		return {
			failed: true,
			code:
				typeof error === "string" && /^[a-zA-Z0-9_-]{1,100}$/.test(error)
					? error
					: "AUTHENTICATION_FAILED",
			pendingMFA: false,
		};
	}
	if (returned instanceof Response && returned.status >= 400)
		return { failed: true, code: "AUTHENTICATION_FAILED", pendingMFA: false };
	if (record?.error)
		return { failed: true, code: "AUTHENTICATION_FAILED", pendingMFA: false };
	return { failed: false, pendingMFA: false };
}

/** Native authentication completion paths; initiating OAuth or sending mail is not a sign-in. */
export function isPrimaryAuthenticationPath(
	path: string,
	body?: Record<string, unknown>,
): boolean {
	if (path === "/phone-number/verify")
		return body?.disableSession !== true && body?.updatePhoneNumber !== true;
	return (
		[
			"/sign-in/email",
			"/sign-in/username",
			"/sign-in/phone-number",
			"/sign-in/email-otp",
			"/email-otp/verify-email",
			"/verify-email",
			"/magic-link/verify",
			"/sign-in/passkey",
			"/passkey/verify-authentication",
			"/siwe/verify",
			"/one-tap/callback",
			"/two-factor/verify-totp",
			"/two-factor/verify-backup-code",
		].includes(path) ||
		/^\/(callback\/|oauth2\/callback\/|sso\/callback\/|sso\/saml2\/sp\/acs)/.test(
			path,
		)
	);
}

/** Useful mutations have stable event names; GET reads and arbitrary request paths are omitted. */
export function mutationEventType(path: string): string | undefined {
	const fixed: Record<string, string> = {
		"/sign-out": "session.signed-out",
		"/revoke-session": "session.revoked",
		"/revoke-sessions": "session.revoked-all",
		"/revoke-other-sessions": "session.revoked-others",
		"/change-password": "user.password-changed",
		"/set-password": "user.password-set",
		"/request-password-reset": "user.password-reset-requested",
		"/reset-password": "user.password-reset",
		"/verify-email": "user.email-verified",
		"/change-email": "user.email-change-requested",
		"/update-user": "user.updated",
		"/delete-user": "user.deleted",
		"/link-social": "account.link-started",
		"/unlink-account": "account.unlinked",
		"/two-factor/enable": "mfa.enrollment-started",
		"/two-factor/disable": "mfa.disabled",
		"/two-factor/generate-backup-codes": "mfa.recovery-codes-rotated",
		"/passkey/verify-registration": "passkey.registered",
		"/passkey/update-passkey": "passkey.updated",
		"/passkey/delete-passkey": "passkey.deleted",
		"/delete-anonymous-user": "user.anonymous-deleted",
		"/phone-number/verify": "user.phone-verified",
		"/phone-number/send-otp": "user.phone-verification-requested",
		"/phone-number/request-password-reset":
			"user.phone-password-reset-requested",
		"/phone-number/reset-password": "user.phone-password-reset",
		"/device/approve": "oauth2.device-approved",
		"/device/deny": "oauth2.device-denied",
	};
	if (fixed[path]) return fixed[path];
	const organizationActions: Record<string, string> = {
		create: "created",
		update: "updated",
		delete: "deleted",
		"add-member": "member.added",
		"remove-member": "member.removed",
		"update-member-role": "member.role-updated",
		"invite-member": "invitation.created",
		"cancel-invitation": "invitation.cancelled",
		"accept-invitation": "invitation.accepted",
		"reject-invitation": "invitation.rejected",
		leave: "member.left",
		"create-team": "team.created",
		"update-team": "team.updated",
		"remove-team": "team.removed",
		"add-team-member": "team.member-added",
		"remove-team-member": "team.member-removed",
		"create-role": "role.created",
		"update-role": "role.updated",
		"delete-role": "role.deleted",
	};
	if (path.startsWith("/organization/")) {
		const action = organizationActions[path.slice("/organization/".length)];
		return action ? `organization.${action}` : undefined;
	}
	if (
		/^\/admin\/(create-user|update-user|set-role|ban-user|unban-user|impersonate-user|stop-impersonating|remove-user|set-user-password|revoke-user-session|revoke-user-sessions)$/.test(
			path,
		)
	)
		return path.slice(1).replaceAll("/", ".");
	if (
		/^\/sso\/(register|update-provider|delete-provider|verify-domain)$/.test(
			path,
		)
	)
		return path.slice(1).replaceAll("/", ".");
	if (
		/^\/api-key\/(create|update|delete|delete-all-expired-api-keys)$/.test(path)
	)
		return path.slice(1).replaceAll("/", ".");
	if (
		/^\/(admin\/)?oauth2\/(create-client|update-client|delete-client|rotate-client-secret|create-resource|update-resource|delete-resource)$/.test(
			path,
		)
	)
		return path.slice(1).replaceAll("/", ".");
	return undefined;
}

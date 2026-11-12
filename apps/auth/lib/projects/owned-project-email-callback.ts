import { applicationMfaCallback } from "../mfa-continuation";
import {
	isAuthenticExpiredProjectIssuerEmailContinuation,
	readSignedProjectIssuerQuery,
} from "./owned-project-issuer-authorization-query";
import { projectOrigin } from "./validation";

type CallbackFlow = "verification" | "password-reset";
type CallbackPhase = "issue" | "consume";

export type OwnedEmailCallbackPolicy = (
	target: URL,
	flow: CallbackFlow,
	phase: CallbackPhase,
) => { url: URL; expiredContinuation?: true } | null;

const localAccountPath =
	/^\/(?:account(?:\/[A-Za-z0-9_-]+)?|organizations(?:\/[A-Za-z0-9_-]+\/sso)?|accept-invitation\/[A-Za-z0-9_-]+)\/?$/;

/** Keep emailed redirects inside the checked project browser surface. */
export function createOwnedProjectEmailCallbackPolicy(options: {
	browserOrigin: string;
	publicLinkBaseURL: string;
	signingSecret: string;
}): OwnedEmailCallbackPolicy {
	const origin = projectOrigin.parse(options.browserOrigin);
	const authPath = new URL(options.publicLinkBaseURL).pathname;
	const account = `${origin}/account`;

	function local(target: URL, phase: CallbackPhase) {
		if (
			target.origin !== origin ||
			target.username ||
			target.password ||
			target.href.length > 2048 ||
			target.searchParams.has("token") ||
			target.searchParams.has("error")
		)
			return null;
		if (target.pathname === "/oauth2/continue") {
			if (target.hash || target.searchParams.getAll("client_id").length !== 1)
				return null;
			const serialized = target.searchParams.toString();
			const live = readSignedProjectIssuerQuery(
				serialized,
				options.signingSecret,
			);
			if (live && !live.consentSessionId) return { url: target };
			return phase === "consume" &&
				isAuthenticExpiredProjectIssuerEmailContinuation(
					serialized,
					options.signingSecret,
				)
				? { url: new URL(account), expiredContinuation: true as const }
				: null;
		}
		if (
			target.pathname !== "/" &&
			!(target.pathname === "/console" && !target.hash) &&
			!localAccountPath.test(target.pathname)
		)
			return null;
		return applicationMfaCallback(target.href, origin, authPath)
			? { url: target }
			: null;
	}

	return (target, flow, phase) => {
		if (flow === "verification") return local(target, phase);
		if (
			target.origin !== origin ||
			target.username ||
			target.password ||
			target.hash ||
			target.pathname !== "/reset-password" ||
			[...target.searchParams.keys()].some((name) => name !== "returnTo")
		)
			return null;
		const values = target.searchParams.getAll("returnTo");
		const intent = values[0];
		if (
			values.length !== 1 ||
			!intent?.startsWith("/") ||
			intent.startsWith("//") ||
			/[\\\u0000-\u0020\u007f]/.test(intent)
		)
			return null;
		const destination = local(new URL(intent, origin), phase);
		if (!destination) return null;
		if (!destination.expiredContinuation) return { url: target };
		const reset = new URL("/reset-password", origin);
		reset.searchParams.set("returnTo", "/account");
		return { url: reset, expiredContinuation: true };
	};
}

import type { PoolClient } from "pg";
import { reservedProjectEmailError } from "../project-email-alias-config";
import {
	projectSecurityBlockedCode,
	projectSecurityBlockedMessage,
} from "./owned-project-security";

export const ssoProfileRejected = "validation_failed";

export interface ProjectSsoAdmission {
	denyProviderProfile?(
		client: PoolClient,
		request: Request,
		email: string,
	): Promise<boolean>;
	prepareProviderSignup?(
		client: PoolClient,
		request: Request,
		email: string,
	): Promise<(() => Promise<void>) | null>;
}

/** Keep the native signup counter outside the provisional SSO identity writes. */
export function createSsoProfileAdmission(
	policy: ProjectSsoAdmission,
	client: PoolClient,
	request: Request,
) {
	const state: { commitDenial?: boolean; rollback?: () => Promise<void> } = {};
	return {
		state,
		async denyProfile(email: string, action: "existing" | "signup") {
			if (action === "signup" && policy.prepareProviderSignup) {
				const rollback = await policy.prepareProviderSignup(
					client,
					request,
					email,
				);
				if (!rollback) state.commitDenial = true;
				else state.rollback = rollback;
				return !rollback;
			}
			return (
				(await policy.denyProviderProfile?.(client, request, email)) === true
			);
		},
	};
}

export function ssoPolicyErrorDescription(code: string) {
	switch (code) {
		case ssoProfileRejected:
			return "User validation failed";
		case projectSecurityBlockedCode:
			return projectSecurityBlockedMessage;
		case reservedProjectEmailError.code:
			return reservedProjectEmailError.message;
	}
}

export async function ssoSessionErrorCode(response: Response) {
	if (response.status === 429) {
		const body: unknown = await response
			.clone()
			.json()
			.catch(() => null);
		if (
			body &&
			typeof body === "object" &&
			"code" in body &&
			body.code === projectSecurityBlockedCode
		)
			return projectSecurityBlockedCode;
	}
	return "account_not_linked";
}

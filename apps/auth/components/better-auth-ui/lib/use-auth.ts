"use client";
import type { AuthClient } from "@better-auth-ui/core";
import { useAuth as useOfficialAuth } from "@better-auth-ui/react";
import { useAllAuthUI } from "./allauth-context";
/** Keep the official UI, while AllAuth owns validated callback and continuation URLs. */
export function useAuth<TAuthClient extends AuthClient = AuthClient>() {
	const auth = useOfficialAuth<TAuthClient>();
	const allauth = useAllAuthUI();
	return {
		...auth,
		...(allauth ? { baseURL: allauth.origin, redirectTo: allauth.redirectTo } : {}),
		signUpEnabled: allauth?.signUpEnabled !== false,
	};
}

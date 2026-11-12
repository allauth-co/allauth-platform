import {
	fetchPublicProjectHttps,
	publicProjectHttpsURL,
} from "./owned-project-https";

export function ssoHttpsUrl(input: string) {
	return publicProjectHttpsURL(input);
}

export type SsoFetch = (
	input: URL | RequestInfo,
	init?: RequestInit,
) => Promise<Response>;

export const fetchPublicSsoEndpoint: SsoFetch = async (input, init) => {
	const request = new Request(input, init);
	ssoHttpsUrl(request.url);
	return fetchPublicProjectHttps(request, { timeoutMs: 8000 });
};

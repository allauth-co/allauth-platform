const loopbackHosts = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** Direct loopback development has no hosting ingress to supply a trusted client IP. */
export function localDevelopmentAuthRequest(request: Request, origin: string, mode: string | undefined): Request {
	if (mode !== "development") return request;
	const configured = new URL(origin);
	if (!loopbackHosts.has(configured.hostname) || configured.origin !== new URL(request.url).origin) return request;
	const headers = new Headers(request.headers);
	headers.set("x-real-ip", "127.0.0.1");
	headers.delete("x-forwarded-for");
	headers.delete("cf-connecting-ip");
	return new Request(request, { headers });
}

import { lookup } from "node:dns/promises";
import { request as httpsRequest } from "node:https";
import { BlockList, isIP } from "node:net";

const excluded = new BlockList();
for (const [address, bits] of [
	["0.0.0.0", 8],
	["10.0.0.0", 8],
	["100.64.0.0", 10],
	["127.0.0.0", 8],
	["169.254.0.0", 16],
	["172.16.0.0", 12],
	["192.0.0.0", 24],
	["192.0.2.0", 24],
	["192.88.99.0", 24],
	["192.168.0.0", 16],
	["198.18.0.0", 15],
	["198.51.100.0", 24],
	["203.0.113.0", 24],
	["224.0.0.0", 4],
	["240.0.0.0", 4],
] as const)
	excluded.addSubnet(address, bits, "ipv4");
for (const [address, bits] of [
	["2001::", 23],
	["2001:db8::", 32],
	["2002::", 16],
	["3ffe::", 16],
	["3fff::", 20],
] as const)
	excluded.addSubnet(address, bits, "ipv6");
const globalIpv6 = new BlockList();
globalIpv6.addSubnet("2000::", 3, "ipv6");

function publicAddress(address: string) {
	const family = isIP(address);
	if (family === 4) return !excluded.check(address, "ipv4");
	return (
		family === 6 &&
		globalIpv6.check(address, "ipv6") &&
		!excluded.check(address, "ipv6")
	);
}

export class UnsafeProjectHttpsTarget extends Error {}

export class ProjectHttpsResponseTooLarge extends Error {}

export function publicProjectHttpsURL(input: string, allowIP = false) {
	const url = new URL(input);
	const hostname = url.hostname.replace(/^\[|\]$/g, "").replace(/\.$/, "");
	if (
		input.length > 2048 ||
		/[\\\u0000-\u0020\u007f]/.test(input) ||
		url.protocol !== "https:" ||
		url.username ||
		url.password ||
		input.includes("#") ||
		(isIP(hostname)
			? !allowIP || !publicAddress(hostname)
			: !hostname.includes(".") ||
				/(?:^|\.)(?:localhost|local|internal)$/.test(hostname) ||
				hostname === "metadata.goog")
	)
		throw new UnsafeProjectHttpsTarget("Invalid outbound project HTTPS URL.");
	return url;
}

/** Resolve and pin a public address while TLS verifies the original hostname. */
export async function fetchPublicProjectHttps(
	request: Request,
	options: {
		timeoutMs: number;
		headersOnly?: boolean;
		maximumResponseBytes?: number;
	},
): Promise<Response> {
	const url = publicProjectHttpsURL(request.url, true);
	const hostname = url.hostname.replace(/^\[|\]$/g, "");
	const family = isIP(hostname);
	const name = hostname.endsWith(".") ? hostname : `${hostname}.`;
	const signal = AbortSignal.any([
		request.signal,
		AbortSignal.timeout(options.timeoutMs),
	]);
	const maximumResponseBytes = options.maximumResponseBytes ?? 256 * 1024;
	let onAbort: (() => void) | undefined;
	try {
		const addresses = family
			? [{ address: hostname, family }]
			: await Promise.race([
					lookup(name, { all: true, order: "verbatim" }),
					new Promise<never>((_, reject) => {
						onAbort = () => reject(signal.reason);
						if (signal.aborted) onAbort();
						else signal.addEventListener("abort", onAbort, { once: true });
					}),
				]);
		if (!addresses.length)
			throw new Error("The outbound HTTPS target did not resolve.");
		if (
			addresses.length > 32 ||
			addresses.some(({ address }) => !publicAddress(address))
		)
			throw new UnsafeProjectHttpsTarget(
				"The outbound HTTPS target must resolve to public addresses.",
			);
		const selected =
			addresses.find(({ family }) => family === 4) ?? addresses[0]!;
		const body = request.body
			? new Uint8Array(await request.arrayBuffer())
			: undefined;
		const requestHeaders = new Headers(request.headers);
		requestHeaders.delete("host");
		requestHeaders.delete("connection");
		if (body) requestHeaders.set("content-length", String(body.byteLength));
		return await new Promise<Response>((resolve, reject) => {
			const outgoing = httpsRequest(
				url,
				{
					method: request.method,
					headers: Object.fromEntries(requestHeaders),
					agent: false,
					rejectUnauthorized: true,
					signal,
					lookup(_hostname, options, callback) {
						if (options.all) callback(null, [selected]);
						else callback(null, selected.address, selected.family);
					},
				},
				(upstream) => {
					const status = upstream.statusCode ?? 502;
					if (status < 200 || status > 599) {
						upstream.destroy();
						reject(new Error("Invalid outbound HTTPS response status."));
						return;
					}
					if (status >= 300 && status < 400) {
						upstream.destroy();
						reject(
							new UnsafeProjectHttpsTarget(
								"Outbound project HTTPS target redirected.",
							),
						);
						return;
					}
					const headers = new Headers();
					for (const [name, value] of Object.entries(upstream.headers)) {
						for (const item of Array.isArray(value)
							? value
							: value
								? [value]
								: [])
							headers.append(name, item);
					}
					if (options.headersOnly) {
						resolve(new Response(null, { status, headers }));
						upstream.destroy();
						return;
					}
					const tooLarge = () =>
						new ProjectHttpsResponseTooLarge(
							"Outbound project HTTPS response is too large.",
						);
					if (Number(headers.get("content-length")) > maximumResponseBytes) {
						upstream.destroy();
						reject(tooLarge());
						return;
					}
					const chunks: Uint8Array[] = [];
					let length = 0;
					upstream.on("data", (chunk: Uint8Array) => {
						length += chunk.length;
						if (length > maximumResponseBytes) upstream.destroy(tooLarge());
						else chunks.push(chunk);
					});
					upstream.on("error", reject);
					upstream.on("end", () => {
						const bytes = new Uint8Array(length);
						let offset = 0;
						for (const chunk of chunks) {
							bytes.set(chunk, offset);
							offset += chunk.length;
						}
						resolve(
							new Response([204, 205].includes(status) ? null : bytes, {
								status,
								headers,
							}),
						);
					});
				},
			);
			outgoing.on("error", reject);
			outgoing.end(body);
		});
	} finally {
		if (onAbort) signal.removeEventListener("abort", onAbort);
	}
}

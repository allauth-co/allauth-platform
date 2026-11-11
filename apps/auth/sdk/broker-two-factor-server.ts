import { createHash } from "node:crypto";
import { appPath } from "./helpers";

/** Enable only when the app renders the matching SDK SignIn challenge. */
export interface AllAuthBrokerTwoFactorOptions {
	signInUrl: string;
}

/** Server-only browser binding and ticket cookies; central AllAuth cookies never enter the app. */
export function createBrokerTwoFactorRoutes(
	project: string,
	app: URL,
	remote: URL,
	configuration: AllAuthBrokerTwoFactorOptions,
) {
	const signIn = new URL(appPath(configuration.signInUrl), app.origin);
	if (signIn.search || signIn.hash || signIn.pathname.startsWith("/api/"))
		throw new Error(
			"Use a local sign-in page without query parameters for brokerTwoFactor.signInUrl.",
		);
	const prefix = `${app.protocol === "https:" ? "__Secure-" : ""}allauth_project_${project}.`;
	const attributes = `; Path=/; HttpOnly; SameSite=Lax${app.protocol === "https:" ? "; Secure" : ""}`;
	const opaque = /^[a-f0-9]{64}$/;
	const cookieValue = (request: Request, name: string) => {
		const matches = (request.headers.get("cookie") || "")
			.split(";")
			.map((value) => value.trim())
			.filter((value) => value.startsWith(`${prefix}${name}=`));
		return matches.length === 1
			? matches[0]!.slice(`${prefix}${name}=`.length)
			: undefined;
	};
	return {
		accept(request: Request): Response {
			const query = new URL(request.url).searchParams;
			const ticket = query.get("ticket") || "";
			const binding = cookieValue(request, "broker_mfa_binding") || "";
			if (
				request.method !== "GET" ||
				query.getAll("ticket").length !== 1 ||
				!opaque.test(ticket) ||
				!opaque.test(binding)
			)
				return Response.json(
					{ error: { message: "This sign-in has expired. Start again." } },
					{
						status: 400,
						headers: {
							"cache-control": "no-store",
							"referrer-policy": "no-referrer",
						},
					},
				);
			const destination = new URL(signIn);
			destination.searchParams.set("challenge", "broker-two-factor");
			return new Response(null, {
				status: 303,
				headers: {
					location: destination.href,
					"set-cookie": `${prefix}broker_mfa_ticket=${ticket}; Max-Age=300${attributes}`,
					"cache-control": "no-store",
					pragma: "no-cache",
					"referrer-policy": "no-referrer",
				},
			});
		},
		decorate(endpoint: string, data: unknown, headers: Headers): unknown {
			if (
				endpoint !== "sign-in/social" ||
				!data ||
				typeof data !== "object" ||
				!("url" in data) ||
				typeof data.url !== "string"
			)
				return data;
			const destination = new URL(data.url, remote.origin);
			if (
				destination.origin !== remote.origin ||
				destination.pathname !== "/api/auth/oauth2/authorize"
			)
				return data;
			const callback = new URL(
				destination.searchParams.get("redirect_uri") || "/",
				remote.origin,
			);
			if (callback.href !== `${app.origin}/api/allauth/callback/allauth`)
				return data;
			const binding = Array.from(
				crypto.getRandomValues(new Uint8Array(32)),
				(byte) => byte.toString(16).padStart(2, "0"),
			).join("");
			destination.searchParams.set("allauth_mfa", "app-v1");
			destination.searchParams.set(
				"allauth_mfa_binding",
				createHash("sha256").update(binding).digest("hex"),
			);
			headers.append(
				"set-cookie",
				`${prefix}broker_mfa_binding=${binding}; Max-Age=600${attributes}`,
			);
			headers.append(
				"set-cookie",
				`${prefix}broker_mfa_ticket=; Max-Age=0${attributes}`,
			);
			return { ...data, url: destination.href };
		},
		clear(headers: Headers) {
			for (const name of ["broker_mfa_ticket", "broker_mfa_binding"])
				headers.append(
					"set-cookie",
					`${prefix}${name}=; Max-Age=0${attributes}`,
				);
		},
		completion(data: unknown, headers: Headers): { url: string } {
			if (
				!data ||
				typeof data !== "object" ||
				!("url" in data) ||
				typeof data.url !== "string"
			)
				throw new Error("Missing broker completion.");
			const destination = new URL(data.url);
			if (
				destination.origin !== remote.origin ||
				destination.pathname !== "/api/broker-two-factor/complete" ||
				destination.username ||
				destination.password ||
				destination.hash ||
				destination.searchParams.getAll("receipt").length !== 1 ||
				[...destination.searchParams.keys()].some((key) => key !== "receipt") ||
				!opaque.test(destination.searchParams.get("receipt") || "")
			)
				throw new Error("Invalid broker completion.");
			this.clear(headers);
			return { url: destination.href };
		},
	};
}

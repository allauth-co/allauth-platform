import type { Pool, PoolClient } from "pg";
import type { Project } from "./registry";
import { projectOrigin, projectSlug } from "./validation";

export type ProjectAccountAuthority = {
	userId: string;
	sessionId: string;
	token: string;
	impersonatedBy: string | null;
	eligible?: boolean;
};

export interface ProjectAccountLinkOptions {
	database: Pool;
	project: Pick<Project, "schemaName" | "slug">;
	baseURL: string;
	basePath: string;
	publicLinkBaseURL: string;
	trustedOrigins: readonly string[];
	/** Read the live signed-cookie session without replacing it or using a cookie cache. */
	authority(
		client: PoolClient,
		request: Request,
	): Promise<ProjectAccountAuthority | null>;
	defer(work: () => Promise<void>): void;
	deliver(input: {
		kind:
			| "change-email-confirmation"
			| "change-email-verification"
			| "delete-account";
		user: { id: string; email: string; name: string };
		url: string;
	}): Promise<void>;
	onDeliveryFailure?(): void;
}

function safeURL(value: string) {
	return Boolean(
		value &&
			value.length <= 2048 &&
			!value.startsWith("//") &&
			!/[\\\u0000-\u0020\u007f]/.test(value),
	);
}

export function accountLinkHeaders(headers = new Headers()) {
	headers.set("Cache-Control", "no-store");
	headers.set("Pragma", "no-cache");
	headers.set("Referrer-Policy", "no-referrer");
	return headers;
}

export function accountLinkJson(
	body: unknown,
	status = 200,
	headers?: Headers,
) {
	return Response.json(body, { status, headers: accountLinkHeaders(headers) });
}

export function accountLinkError(
	status: number,
	code: string,
	message: string,
) {
	return accountLinkJson({ code, message }, status);
}

export function accountLinkRedirect(url: URL, headers = new Headers()) {
	headers.set("Location", url.href);
	return new Response(null, {
		status: 302,
		headers: accountLinkHeaders(headers),
	});
}

export function createProjectAccountLinks(options: ProjectAccountLinkOptions) {
	const origin = projectOrigin.parse(options.baseURL);
	const slug = projectSlug.parse(options.project.slug);
	const origins = new Set([
		origin,
		...options.trustedOrigins.map((value) => projectOrigin.parse(value)),
	]);
	const publicLink = new URL(options.publicLinkBaseURL);
	if (
		![`/api/projects/${slug}/auth`, "/api/auth"].includes(options.basePath) ||
		!safeURL(options.publicLinkBaseURL) ||
		!origins.has(publicLink.origin) ||
		publicLink.username ||
		publicLink.password ||
		publicLink.search ||
		publicLink.hash ||
		![`/api/projects/${slug}/auth`, "/api/auth", "/api/allauth"].includes(
			publicLink.pathname,
		)
	)
		throw new Error("Invalid project account link configuration.");

	function requestURL(request: Request, method: "GET" | "POST", path: string) {
		const url = new URL(request.url);
		const caller = request.headers.get("origin");
		if (
			request.method !== method ||
			url.origin !== origin ||
			url.pathname !== `${options.basePath}${path}` ||
			request.headers.has("authorization") ||
			(caller !== null && !origins.has(caller)) ||
			(method === "POST" &&
				(!caller || request.headers.get("sec-fetch-site") === "cross-site"))
		)
			return null;
		return url;
	}

	function callback(value: string | undefined, base = publicLink.origin) {
		if (
			!safeURL(value ?? "/") ||
			(value !== undefined &&
				!value.startsWith("/") &&
				!/^https?:\/\//i.test(value))
		)
			return null;
		try {
			const url = new URL(value ?? "/", base);
			if (
				!origins.has(url.origin) ||
				url.username ||
				url.password ||
				url.searchParams.has("token")
			)
				return null;
			return url;
		} catch {
			return null;
		}
	}

	function mail(path: string, token: string, destination: URL) {
		const url = new URL(`${publicLink.pathname}${path}`, publicLink.origin);
		url.searchParams.set("token", token);
		url.searchParams.set("callbackURL", destination.href);
		return url.href;
	}

	function schedule(
		input: Parameters<ProjectAccountLinkOptions["deliver"]>[0],
	) {
		options.defer(async () => {
			try {
				await options.deliver(input);
			} catch {
				options.onDeliveryFailure?.();
			}
		});
	}

	return { requestURL, callback, mail, schedule };
}

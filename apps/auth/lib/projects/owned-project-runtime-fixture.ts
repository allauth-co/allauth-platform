import type { IncomingMessage, ServerResponse } from "node:http";
import { createServer } from "node:http";
import { APIError } from "better-auth";
import { GET as openid } from "../../app/.well-known/openid-configuration/route";
import * as consoleOrganizations from "../../app/api/admin/organizations/route";
import * as hosted from "../../app/api/auth/[...all]/route";
import { GET as config } from "../../app/api/config/route";
import { GET as health } from "../../app/api/health/route";
import * as projectAuth from "../../app/api/projects/[slug]/auth/[...all]/route";
import { GET as brokerLogin } from "../../app/oauth/login/route";
import { authOrigin } from "../configuration";
import { resolveHostedBinding } from "../domains/hosting";
import { readProjectAppleProvider } from "../project-providers/apple";
import { createOwnedProjectRuntimeCandidate } from "./owned-project-runtime-factory";
import { runtimeProviderFixtureFetch } from "./owned-project-runtime-provider-fixture";
import { getProject, projectRegistryPool } from "./registry";
import {
	closeProjectInstances,
	installIsolatedProjectEngineFixture,
	withHostedProjectAuthEngine,
	withProjectAuthEngine,
} from "./runtime";

export interface ProjectRuntimeFixtureBoot {
	databaseURL: string;
	projectId: string;
	projectSlug: string;
	schemaName: string;
	owned: boolean;
	appleIssuerKey?: string;
}

const trustedFixtureIP = "192.0.2.55";

async function requestFromHTTP(incoming: IncomingMessage) {
	const headers = new Headers();
	for (const [name, value] of Object.entries(incoming.headers)) {
		if (name === "host" || name === "x-real-ip") continue;
		for (const item of Array.isArray(value) ? value : value ? [value] : [])
			headers.append(name, item);
	}
	headers.set("x-real-ip", trustedFixtureIP);
	const method = incoming.method ?? "GET";
	const chunks: Uint8Array[] = [];
	let size = 0;
	for await (const chunk of incoming) {
		const bytes =
			typeof chunk === "string" ? Buffer.from(chunk) : (chunk as Uint8Array);
		size += bytes.byteLength;
		if (size > 262_144) throw new Error("Fixture request is too large.");
		chunks.push(bytes);
	}
	const body = chunks.length ? Buffer.concat(chunks) : undefined;
	const origin = authOrigin(process.env);
	const url = new URL(incoming.url ?? "/", origin);
	if (url.origin !== origin)
		throw new Error("Fixture request must use its own HTTP listener.");
	return new Request(url, { method, headers, body });
}

async function dispatch(request: Request) {
	const path = new URL(request.url).pathname;
	if (request.method === "GET" && path === "/.well-known/openid-configuration")
		return openid(request);
	if (request.method === "GET" && path === "/api/health") return health();
	if (request.method === "GET" && path === "/api/config")
		return config(request);
	if (request.method === "GET" && path === "/oauth/login")
		return brokerLogin(request);
	if (path === "/api/admin/organizations") {
		if (request.method === "GET") return consoleOrganizations.GET(request);
		if (request.method === "POST") return consoleOrganizations.POST(request);
	}
	const project = /^\/api\/projects\/([^/]+)\/auth\//.exec(path);
	if (project) {
		const context = { params: Promise.resolve({ slug: project[1]! }) };
		if (request.method === "GET") return projectAuth.GET(request, context);
		if (request.method === "POST") return projectAuth.POST(request, context);
	}
	if (path.startsWith("/api/auth/")) {
		if (request.method === "GET") return hosted.GET(request);
		if (request.method === "POST") return hosted.POST(request);
	}
	return new Response(null, { status: 404 });
}

async function reply(response: ServerResponse, result: Response) {
	response.statusCode = result.status;
	for (const [name, value] of result.headers) {
		if (name !== "set-cookie") response.setHeader(name, value);
	}
	const cookies = result.headers.getSetCookie();
	if (cookies.length) response.setHeader("set-cookie", cookies);
	response.end(Buffer.from(await result.arrayBuffer()));
}

async function boot(selection: ProjectRuntimeFixtureBoot) {
	const url = new URL(selection.databaseURL);
	if (
		process.env.NODE_ENV !== "test" ||
		url.hostname !== "127.0.0.1" ||
		url.port !== "55445" ||
		!/^\/allauth_hosted_[a-f0-9]{32}$/.test(url.pathname) ||
		!process.send
	)
		throw new Error(
			"The project HTTP fixture requires its isolated PostgreSQL and IPC parent.",
		);
	process.env.DATABASE_URL = url.href;
	const outboundDisabled = () => {
		throw new Error(
			"This project HTTP fixture does not perform outbound HTTP.",
		);
	};
	const apple = readProjectAppleProvider(process.env, selection.projectSlug);
	globalThis.fetch = Object.assign(
		runtimeProviderFixtureFetch(
			apple && selection.appleIssuerKey
				? {
						credentialKey: apple.privateKey,
						issuerKey: selection.appleIssuerKey,
					}
				: undefined,
		),
		{
			preconnect: outboundDisabled,
		},
	);
	const pending = new Set<Promise<void>>();
	if (selection.owned) {
		const env = {
			...process.env,
			EMAIL: {
				async send(message: { to: string; subject: string; text: string }) {
					process.send?.({
						mail: {
							to: message.to,
							subject: message.subject,
							text: message.text,
						},
					});
				},
			},
		};
		installIsolatedProjectEngineFixture({
			projectId: selection.projectId,
			schemaName: selection.schemaName,
			databaseURL: url.href,
			build: ({
				database,
				project,
				policy,
				baseURL,
				basePath,
				signingSecret,
			}) =>
				createOwnedProjectRuntimeCandidate({
					database,
					project,
					policy,
					env,
					transport:
						basePath === "/api/auth"
							? { kind: "hosted", origin: baseURL }
							: { kind: "direct" },
					signingSecret,
					trustedIP: (request) => request.headers.get("x-real-ip"),
					defer(work) {
						const operation = Promise.resolve()
							.then(work)
							.catch(() => undefined);
						pending.add(operation);
						void operation.finally(() => pending.delete(operation));
					},
					async fetchPasswordRange(request) {
						const url = new URL(request.url);
						if (
							url.origin !== "https://api.pwnedpasswords.com" ||
							!/^\/range\/[0-9A-F]{5}$/.test(url.pathname) ||
							request.headers.get("add-padding") !== "true"
						)
							outboundDisabled();
						return new Response(`${"F".repeat(35)}:0\r\n`);
					},
					async postBackchannelLogout(destination, payload) {
						if (
							destination.href !== "https://rp.runtime.fixture.example/logout"
						)
							outboundDisabled();
						process.send?.({ logout: payload.get("logout_token") });
						return 204;
					},
				}),
		});
		const project = await getProject(selection.projectSlug, env);
		const host = `${project.slug}-accounts.allauth.co`;
		const binding = await resolveHostedBinding(host, env);
		if (
			project.id !== selection.projectId ||
			project.schemaName !== selection.schemaName ||
			binding?.project.id !== project.id
		)
			throw new Error(
				"Fixture project or hosted binding did not match startup authority.",
			);
		await withProjectAuthEngine(project.slug, async () => undefined, env);
		await withHostedProjectAuthEngine(
			binding.project,
			host,
			async () => undefined,
			env,
		);
	}
	const server = createServer(async (incoming, response) => {
		try {
			await reply(response, await dispatch(await requestFromHTTP(incoming)));
		} catch (error) {
			if (response.headersSent) {
				response.destroy();
				return;
			}
			await reply(
				response,
				Response.json(
					{ error: "Fixture HTTP handler rejected the request." },
					{
						status: error instanceof APIError ? error.statusCode : 500,
					},
				),
			);
		}
	});
	server.listen(0, "127.0.0.1", () => {
		const address = server.address();
		if (address && typeof address !== "string")
			process.send?.({ port: address.port });
	});
	process.on("message", (message: unknown) => {
		if (message !== "stop") return;
		server.close(async () => {
			try {
				await Promise.allSettled(pending);
				await Promise.all([
					closeProjectInstances(),
					projectRegistryPool(process.env).end(),
				]);
				process.exit(0);
			} catch {
				process.exit(1);
			}
		});
	});
}

if (!process.send)
	throw new Error(
		"Start the isolated project HTTP fixture from its PostgreSQL test.",
	);
process.once("message", (message: ProjectRuntimeFixtureBoot) => {
	void boot(message).catch((error: unknown) => {
		const known =
			error instanceof Error &&
			/^(This development project|The development candidate|The selected development project|Invalid project hosted binding|Fixture project or hosted binding)\b/.test(
				error.message,
			);
		console.error(
			"Project runtime fixture boot failed",
			error instanceof Error
				? known
					? error.message
					: error.name
				: "UnknownError",
		);
		process.exit(1);
	});
});

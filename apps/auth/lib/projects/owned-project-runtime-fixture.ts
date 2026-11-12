import type { IncomingMessage, ServerResponse } from "node:http";
import { createServer } from "node:http";
import { APIError } from "better-auth";
import * as consoleOrganizations from "../../app/api/admin/organizations/route";
import * as hosted from "../../app/api/auth/[...all]/route";
import { GET as config } from "../../app/api/config/route";
import { GET as health } from "../../app/api/health/route";
import * as projectAuth from "../../app/api/projects/[slug]/auth/[...all]/route";
import { GET as brokerLogin } from "../../app/oauth/login/route";
import { authOrigin } from "../configuration";
import { createOwnedProjectEngine } from "./owned-project-engine";
import { projectRegistryPool } from "./registry";
import {
	closeProjectInstances,
	installIsolatedProjectEngineFixture,
} from "./runtime";

export interface ProjectRuntimeFixtureBoot {
	databaseURL: string;
	projectId: string;
	schemaName: string;
	owned: boolean;
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
	globalThis.fetch = Object.assign(async () => outboundDisabled(), {
		preconnect: outboundDisabled,
	});
	if (selection.owned)
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
				createOwnedProjectEngine({
					database,
					project,
					policy,
					baseURL,
					basePath,
					trustedOrigins: project.origins,
					signingSecret,
					trustedIP: () => trustedFixtureIP,
					security: { requireTrustedIP: true },
					passwordChange: { checkPasswordSafety: async () => "allowed" },
				}),
		});
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
	void boot(message).catch(() => process.exit(1));
});

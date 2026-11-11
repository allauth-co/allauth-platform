import { mkdtemp, readFile, chmod, symlink, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createClient, normalizeBaseURL } from "./client.js";
import { loadCredentials, saveCredentials } from "./credentials.js";
import { login, logout, updateCookieJar } from "./login.js";
import { publicErrorMessage } from "./errors.js";

let directory: string;
let credentialsFile: string;
beforeEach(async () => {
	directory = await mkdtemp(join(tmpdir(), "allauth-mcp-client-"));
	credentialsFile = join(directory, "allauth", "credentials.json");
	vi.stubEnv("ALLAUTH_COOKIE", "");
	vi.stubEnv("ALLAUTH_COOKIE_FILE", "");
	vi.stubEnv("ALLAUTH_CREDENTIALS_FILE", credentialsFile);
	vi.stubEnv("ALLAUTH_URL", "https://allauth.example");
});
afterEach(async () => { vi.unstubAllEnvs(); await rm(directory, { recursive: true, force: true }); });

const json = (body: unknown, headers?: HeadersInit, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });

describe("management HTTP client", () => {
	it("requires exact secure origins and confines HTTP to loopback", () => {
		for (const value of ["https://user:password@example.com", "https://example.com/path", "https://example.com?cookie=secret", "https://example.com/#fragment", "http://example.com", "file:///etc/passwd", "invalid"]) expect(() => normalizeBaseURL(value)).toThrow();
		expect(normalizeBaseURL("https://allauth.co/")).toBe("https://allauth.co");
		expect(normalizeBaseURL("http://localhost:3000")).toBe("http://localhost:3000");
		expect(normalizeBaseURL("http://[::1]:3000")).toBe("http://[::1]:3000");
	});

	it("uses root cookies and same-origin headers without bearer authorization", async () => {
		const transport = vi.fn<typeof fetch>().mockResolvedValue(json({ workspaces: [] }));
		const client = await createClient({ cookie: "allauth.session_token=signed-secret", fetch: transport });
		await expect(client.request({ method: "GET", path: "/api/admin/users", query: { project: "demo-dev", search: "a&b@example.com", limit: 25 } })).resolves.toEqual({ workspaces: [] });
		const [url, init] = transport.mock.calls[0]!;
		expect(new URL(String(url)).searchParams.get("search")).toBe("a&b@example.com");
		expect(init?.redirect).toBe("error");
		const headers = new Headers(init?.headers);
		expect(headers.get("origin")).toBe("https://allauth.example");
		expect(headers.get("cookie")).toBe("allauth.session_token=signed-secret");
		expect(headers.has("authorization")).toBe(false);
	});

	it("rejects non-management, cross-origin and traversal paths before transport", async () => {
		const transport = vi.fn<typeof fetch>();
		const client = await createClient({ cookie: "session=value", fetch: transport });
		for (const path of ["https://evil.example/api/admin/users", "//evil.example/api/admin/users", "/api/auth/sign-in/email", "/api/admin/../auth/sign-in/email", "/api/admin/%2e%2e/auth/sign-in/email", "/api/projects/demo-dev/auth/organization/delete", "/api/admin/users?project=demo-dev", "/api/admin/users#fragment"]) await expect(client.request({ method: "POST", path })).rejects.toThrow("allowlist");
		expect(transport).not.toHaveBeenCalled();
	});

	it("does not serialize multipart branding uploads as JSON", async () => {
		const transport = vi.fn<typeof fetch>().mockResolvedValue(json({ url: "https://assets.example/logo.png" }));
		const client = await createClient({ cookie: "session=value", fetch: transport });
		const body = new FormData(); body.set("kind", "logo"); body.set("file", new Blob([new Uint8Array([1, 2, 3])], { type: "image/png" }), "logo.png");
		await client.request({ method: "POST", path: "/api/admin/application-settings/assets", query: { project: "demo-dev" }, body });
		const init = transport.mock.calls[0]![1];
		expect(init?.body).toBe(body);
		expect(new Headers(init?.headers).has("content-type")).toBe(false);
	});

	it("never includes remote error bodies or network errors containing credentials", async () => {
		const transport = vi.fn<typeof fetch>().mockResolvedValue(new Response("secret-cookie password=secret", { status: 401 }));
		const client = await createClient({ cookie: "session=private", fetch: transport });
		await expect(client.request({ method: "GET", path: "/api/workspaces" })).rejects.toThrow(/^AllAuth returned HTTP 401\./);
		transport.mockRejectedValue(new Error("network error Cookie: session=private"));
		await expect(client.request({ method: "GET", path: "/api/workspaces" })).rejects.toThrow(/^The AllAuth request failed\./);
	});

	it("bounds streamed response bytes even without a content length", async () => {
		const transport = vi.fn<typeof fetch>().mockResolvedValue(json({ data: "large payload containing a secret" }));
		const client = await createClient({ cookie: "session=value", fetch: transport, maxResponseBytes: 8 });
		await expect(client.request({ method: "GET", path: "/api/workspaces" })).rejects.toThrow("too large");
	});

	it("aborts timed out requests without retrying writes", async () => {
		const transport = vi.fn<typeof fetch>().mockImplementation(async (_url, init) => new Promise<Response>((_resolve, reject) => init?.signal?.addEventListener("abort", () => reject(new Error("aborted")))));
		const client = await createClient({ cookie: "session=value", fetch: transport, timeoutMs: 5 });
		await expect(client.request({ method: "POST", path: "/api/workspaces", body: { name: "Test" } })).rejects.toThrow("outcome may be unknown");
		expect(transport).toHaveBeenCalledTimes(1);
	});

	it("keeps the timeout active while reading a streamed response", async () => {
		const transport = vi.fn<typeof fetch>().mockImplementation(async (_url, init) => new Response(new ReadableStream<Uint8Array>({ start(controller) { init?.signal?.addEventListener("abort", () => controller.error(new Error("unsafe transport detail"))); } }), { headers: { "Content-Type": "application/json" } }));
		const client = await createClient({ cookie: "session=value", fetch: transport, timeoutMs: 5 });
		await expect(client.request({ method: "GET", path: "/api/workspaces" })).rejects.toThrow("response timed out");
	});

	it("exposes only controlled error messages to the CLI and MCP layer", async () => {
		const transport = vi.fn<typeof fetch>().mockResolvedValue(json({ secret: "private" }, undefined, 403));
		const client = await createClient({ cookie: "session=value", fetch: transport });
		try { await client.request({ method: "GET", path: "/api/workspaces" }); throw new Error("expected a failure"); }
		catch (error) { expect(publicErrorMessage(error)).toContain("HTTP 403"); }
		expect(publicErrorMessage(new Error("Provider leaked password=private"))).toBeUndefined();
	});
});

describe("private root credentials", () => {
	it("keeps sessions private and indexed by the exact origin", async () => {
		await saveCredentials("https://allauth.example", "session=one", credentialsFile);
		await saveCredentials("https://other.example", "session=two", credentialsFile);
		expect(await loadCredentials("https://allauth.example", credentialsFile)).toBe("session=one");
		expect(await loadCredentials("https://missing.example", credentialsFile)).toBeUndefined();
		if (process.platform !== "win32") {
			expect((await stat(credentialsFile)).mode & 0o777).toBe(0o600);
			expect((await stat(join(directory, "allauth"))).mode & 0o777).toBe(0o700);
		}
		await logout({ baseURL: "https://allauth.example", credentialsFile });
		expect(await loadCredentials("https://allauth.example", credentialsFile)).toBeUndefined();
		expect(await loadCredentials("https://other.example", credentialsFile)).toBe("session=two");
	});

	it("refuses to use another origin's saved session", async () => {
		await saveCredentials("https://first.example", "session=private", credentialsFile);
		await expect(createClient({ baseURL: "https://second.example", credentialsFile })).rejects.toThrow("No AllAuth session");
	});

	it("refuses public credential files and symbolic links", async () => {
		await saveCredentials("https://allauth.example", "session=private", credentialsFile);
		if (process.platform !== "win32") {
			await chmod(credentialsFile, 0o644);
			await expect(loadCredentials("https://allauth.example", credentialsFile)).rejects.toThrow("chmod 600");
			await chmod(credentialsFile, 0o600);
			const link = join(directory, "linked.json"); await symlink(credentialsFile, link);
			await expect(loadCredentials("https://allauth.example", link)).rejects.toThrow("symbolic links");
		}
	});

	it("refuses to write credentials into a directory writable by other users", async () => {
		if (process.platform === "win32") return;
		await saveCredentials("https://allauth.example", "session=private", credentialsFile);
		await chmod(join(directory, "allauth"), 0o777);
		await expect(saveCredentials("https://allauth.example", "session=new-private", credentialsFile)).rejects.toThrow("credential directory");
		await chmod(join(directory, "allauth"), 0o700);
		expect(await loadCredentials("https://allauth.example", credentialsFile)).toBe("session=private");
	});
});

describe("headless root login", () => {
	it("saves only after the root session passes management admission", async () => {
		const transport = vi.fn<typeof fetch>()
			.mockResolvedValueOnce(json({ user: { id: "root" } }, { "set-cookie": "allauth.session_token=complete; Path=/; HttpOnly; Secure" }))
			.mockResolvedValueOnce(json({ workspaces: [] }));
		const prompt = vi.fn().mockResolvedValueOnce("owner@example.com").mockResolvedValueOnce("password-hidden");
		await login({ fetch: transport, prompt, credentialsFile });
		expect(prompt.mock.calls[1]).toEqual(["Password: ", true]);
		expect(await loadCredentials("https://allauth.example", credentialsFile)).toBe("allauth.session_token=complete");
		expect(new URL(String(transport.mock.calls[1]![0])).pathname).toBe("/api/workspaces");
		expect(await readFile(credentialsFile, "utf8")).not.toContain("password-hidden");
	});

	it.each(["totp", "recovery"])("completes %s MFA and discards the deleted challenge cookie", async (method) => {
		const complete = new Headers({ "Content-Type": "application/json" });
		complete.append("set-cookie", "allauth.two_factor=; Max-Age=0; Path=/");
		complete.append("set-cookie", "allauth.session_token=complete; HttpOnly; Path=/");
		const transport = vi.fn<typeof fetch>()
			.mockResolvedValueOnce(json({ twoFactorRedirect: true, twoFactorMethods: ["totp"] }, { "set-cookie": "allauth.two_factor=challenge; Path=/; HttpOnly" }))
			.mockResolvedValueOnce(new Response(JSON.stringify({ user: { id: "root" } }), { headers: complete }))
			.mockResolvedValueOnce(json({ workspaces: [] }));
		const prompt = vi.fn().mockResolvedValueOnce("owner@example.com").mockResolvedValueOnce("password-hidden").mockResolvedValueOnce(method).mockResolvedValueOnce("123456");
		await login({ fetch: transport, prompt, credentialsFile });
		const [url, init] = transport.mock.calls[1]!;
		expect(new URL(String(url)).pathname).toBe(method === "recovery" ? "/api/auth/two-factor/verify-backup-code" : "/api/auth/two-factor/verify-totp");
		expect(new Headers(init?.headers).get("cookie")).toBe("allauth.two_factor=challenge");
		expect(JSON.parse(String(init?.body))).toEqual({ code: "123456", trustDevice: false });
		expect(await loadCredentials("https://allauth.example", credentialsFile)).toBe("allauth.session_token=complete");
	});

	it("never saves a partial MFA session or a root session rejected by management", async () => {
		const transport = vi.fn<typeof fetch>()
			.mockResolvedValueOnce(json({ twoFactorRedirect: true }, { "set-cookie": "allauth.two_factor=challenge; Path=/" }))
			.mockResolvedValueOnce(json({ message: "secret challenge" }, undefined, 401));
		const prompt = vi.fn().mockResolvedValueOnce("owner@example.com").mockResolvedValueOnce("password-hidden").mockResolvedValueOnce("totp").mockResolvedValueOnce("badcode");
		await expect(login({ fetch: transport, prompt, credentialsFile })).rejects.toThrow("HTTP 401");
		expect(await loadCredentials("https://allauth.example", credentialsFile)).toBeUndefined();
		transport.mockResolvedValueOnce(json({ user: {} }, { "set-cookie": "allauth.session_token=unverified; Path=/" })).mockResolvedValueOnce(json({ error: "not verified" }, undefined, 403));
		prompt.mockResolvedValueOnce("owner@example.com").mockResolvedValueOnce("password-hidden");
		await expect(login({ fetch: transport, prompt, credentialsFile })).rejects.toThrow("HTTP 403");
		expect(await loadCredentials("https://allauth.example", credentialsFile)).toBeUndefined();
	});

	it("honors cookie deletions, including Expires commas and max-age precedence", () => {
		const jar = new Map([["old", "stale"], ["expired", "stale"]]);
		const headers = new Headers();
		headers.append("set-cookie", "old=gone; Max-Age=0; Expires=Wed, 01 Jan 2098 00:00:00 GMT");
		headers.append("set-cookie", "expired=gone; Expires=Wed, 01 Jan 2020 00:00:00 GMT");
		headers.append("set-cookie", "current=valid; Max-Age=60; Expires=Wed, 01 Jan 2020 00:00:00 GMT");
		updateCookieJar(jar, headers);
		expect([...jar]).toEqual([["current", "valid"]]);
	});
});

import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { loadCredentials } from "./credentials.js";
import { loginDevice } from "./device-login.js";
import { publicErrorMessage } from "./errors.js";

let directory: string;
let credentialsFile: string;
const baseURL = "https://allauth.example";
const deviceCode = "private-device-code-never-print";
const accessToken = "private-access-token-never-save";
const approval = {
	device_code: deviceCode,
	user_code: "ABCD-1234",
	verification_uri: `${baseURL}/device`,
	verification_uri_complete: `${baseURL}/device?user_code=ABCD-1234`,
	expires_in: 600,
	interval: 5,
};
const token = {
	access_token: accessToken,
	token_type: "Bearer",
	expires_in: 3600,
	scope: "",
};
const json = (value: unknown, status = 200, headers?: HeadersInit) =>
	new Response(JSON.stringify(value), {
		status,
		headers: { "Content-Type": "application/json", ...headers },
	});

beforeEach(async () => {
	directory = await mkdtemp(join(tmpdir(), "allauth-mcp-device-"));
	credentialsFile = join(directory, "private", "credentials.json");
	vi.stubEnv("ALLAUTH_COOKIE", "");
	vi.stubEnv("ALLAUTH_COOKIE_FILE", "");
	vi.stubEnv("ALLAUTH_CREDENTIALS_FILE", credentialsFile);
	vi.stubEnv("ALLAUTH_URL", baseURL);
});
afterEach(async () => {
	vi.unstubAllEnvs();
	await rm(directory, { recursive: true, force: true });
});

function clock() {
	let time = 100000;
	return {
		now: () => time,
		sleep: vi.fn(async (milliseconds: number) => {
			time += milliseconds;
		}),
	};
}

describe("first-party device login", () => {
	it("sends no browser fetch metadata over the real Node HTTP transport", async () => {
		const received: Array<{
			path: string;
			headers: Record<string, string | string[] | undefined>;
		}> = [];
		const server = createServer((request, response) => {
			received.push({ path: request.url || "", headers: request.headers });
			const address = server.address();
			if (!address || typeof address === "string")
				throw new Error("Missing fixture address");
			const origin = `http://127.0.0.1:${address.port}`;
			response.setHeader("Content-Type", "application/json");
			if (request.url === "/api/auth/device/code")
				response.end(
					JSON.stringify({
						...approval,
						verification_uri: `${origin}/device`,
						verification_uri_complete: `${origin}/device?user_code=ABCD-1234`,
					}),
				);
			else if (request.url === "/api/auth/device/token") {
				response.setHeader(
					"Set-Cookie",
					"better-auth.session_token=completed.signature; Path=/; HttpOnly",
				);
				response.end(JSON.stringify(token));
			} else if (request.url === "/api/workspaces")
				response.end(JSON.stringify({ workspaces: [] }));
			else {
				response.statusCode = 404;
				response.end("{}");
			}
		});
		await new Promise<void>((resolve) => {
			server.listen(0, "127.0.0.1", resolve);
		});
		try {
			const address = server.address();
			if (!address || typeof address === "string")
				throw new Error("Missing fixture address");
			const origin = `http://127.0.0.1:${address.port}`;
			await loginDevice({
				baseURL: origin,
				notify: vi.fn(),
				...clock(),
				credentialsFile,
			});
			for (const entry of received.filter(({ path }) =>
				path.startsWith("/api/auth/device/"),
			))
				for (const header of [
					"origin",
					"sec-fetch-site",
					"sec-fetch-mode",
					"sec-fetch-dest",
					"authorization",
					"cookie",
				])
					expect(entry.headers[header]).toBeUndefined();
			expect(received.map(({ path }) => path)).toEqual([
				"/api/auth/device/code",
				"/api/auth/device/token",
				"/api/workspaces",
			]);
			expect(await loadCredentials(origin, credentialsFile)).toBe(
				"better-auth.session_token=completed.signature",
			);
		} finally {
			await new Promise<void>((resolve, reject) => {
				server.close((error) => (error ? reject(error) : resolve()));
				server.closeAllConnections();
			});
		}
	});

	it("prints only the approval URL/code and saves the issued cookie after management admission", async () => {
		const transport = vi
			.fn<typeof fetch>()
			.mockResolvedValueOnce(json(approval))
			.mockResolvedValueOnce(
				json(
					{ error: "authorization_pending", error_description: deviceCode },
					400,
				),
			)
			.mockResolvedValueOnce(
				json(token, 200, {
					"set-cookie":
						"__Secure-better-auth.session_token=properly.signed; Path=/; HttpOnly; Secure",
				}),
			)
			.mockResolvedValueOnce(json({ workspaces: [] }));
		const notify = vi.fn();
		const timing = clock();
		await loginDevice({ fetch: transport, notify, ...timing, credentialsFile });
		expect(timing.sleep.mock.calls).toEqual([[5000], [5000]]);
		const printed = notify.mock.calls.flat().join("\n");
		expect(printed).toContain(approval.verification_uri_complete);
		expect(printed).toContain(approval.user_code);
		expect(printed).not.toContain(deviceCode);
		expect(printed).not.toContain(accessToken);
		for (const [url, init] of transport.mock.calls.slice(0, 3)) {
			expect(new URL(String(url)).origin).toBe(baseURL);
			expect(init?.redirect).toBe("error");
			const headers = new Headers(init?.headers);
			for (const name of [
				"Origin",
				"Sec-Fetch-Site",
				"Authorization",
				"Cookie",
			])
				expect(headers.has(name)).toBe(false);
		}
		expect(JSON.parse(String(transport.mock.calls[0]![1]?.body))).toEqual({
			client_id: "allauth-mcp",
		});
		expect(JSON.parse(String(transport.mock.calls[1]![1]?.body))).toEqual({
			grant_type: "urn:ietf:params:oauth:grant-type:device_code",
			device_code: deviceCode,
			client_id: "allauth-mcp",
		});
		expect(
			new Headers(transport.mock.calls[3]![1]?.headers).get("cookie"),
		).toBe("__Secure-better-auth.session_token=properly.signed");
		expect(await loadCredentials(baseURL, credentialsFile)).toBe(
			"__Secure-better-auth.session_token=properly.signed",
		);
		expect(await readFile(credentialsFile, "utf8")).not.toContain(accessToken);
	});

	it("increases every subsequent polling interval by five seconds on slow_down", async () => {
		const transport = vi
			.fn<typeof fetch>()
			.mockResolvedValueOnce(json(approval))
			.mockResolvedValueOnce(json({ error: "slow_down" }, 400))
			.mockResolvedValueOnce(json({ error: "authorization_pending" }, 400))
			.mockResolvedValueOnce(json({ error: "slow_down" }, 400))
			.mockResolvedValueOnce(json({ error: "access_denied" }, 400));
		const timing = clock();
		await expect(
			loginDevice({
				fetch: transport,
				notify: vi.fn(),
				...timing,
				credentialsFile,
			}),
		).rejects.toThrow("denied");
		expect(timing.sleep.mock.calls).toEqual([
			[5000],
			[10000],
			[10000],
			[15000],
		]);
		expect(await loadCredentials(baseURL, credentialsFile)).toBeUndefined();
	});

	it("uses the plain verification URI when no complete link is returned", async () => {
		const {
			verification_uri_complete: _complete,
			interval: _interval,
			...withoutComplete
		} = approval;
		const transport = vi
			.fn<typeof fetch>()
			.mockResolvedValueOnce(json(withoutComplete))
			.mockResolvedValueOnce(json({ error: "access_denied" }, 400));
		const notify = vi.fn();
		const timing = clock();
		await expect(
			loginDevice({ fetch: transport, notify, ...timing, credentialsFile }),
		).rejects.toThrow("denied");
		expect(notify.mock.calls[0]![0]).toContain(
			`${baseURL}/device\nUser code: ABCD-1234`,
		);
		expect(timing.sleep.mock.calls).toEqual([[5000]]);
	});

	it("breaks long slowed polling waits into chunks no longer than sixty seconds", async () => {
		const transport = vi
			.fn<typeof fetch>()
			.mockResolvedValueOnce(json({ ...approval, interval: 60 }))
			.mockResolvedValueOnce(json({ error: "slow_down" }, 400))
			.mockResolvedValueOnce(json({ error: "access_denied" }, 400));
		const timing = clock();
		await expect(
			loginDevice({
				fetch: transport,
				notify: vi.fn(),
				...timing,
				credentialsFile,
			}),
		).rejects.toThrow("denied");
		expect(timing.sleep.mock.calls).toEqual([[60000], [60000], [5000]]);
	});

	it.each([
		"access_denied",
		"expired_token",
		"invalid_grant",
		"invalid_request",
	])("stops immediately on %s without retrying or storing credentials", async (error) => {
		const transport = vi
			.fn<typeof fetch>()
			.mockResolvedValueOnce(json(approval))
			.mockResolvedValueOnce(
				json({ error, error_description: accessToken }, 400),
			);
		try {
			await loginDevice({
				fetch: transport,
				notify: vi.fn(),
				...clock(),
				credentialsFile,
			});
			throw new Error("Expected failure");
		} catch (failure) {
			expect(publicErrorMessage(failure)).toBeDefined();
			expect(String(failure)).not.toContain(accessToken);
		}
		expect(transport).toHaveBeenCalledTimes(2);
		expect(await loadCredentials(baseURL, credentialsFile)).toBeUndefined();
	});

	it("expires locally before the next poll rather than polling past the advertised deadline", async () => {
		const transport = vi
			.fn<typeof fetch>()
			.mockResolvedValueOnce(json({ ...approval, expires_in: 8 }))
			.mockResolvedValueOnce(json({ error: "authorization_pending" }, 400));
		await expect(
			loginDevice({
				fetch: transport,
				notify: vi.fn(),
				...clock(),
				credentialsFile,
			}),
		).rejects.toThrow("expired");
		expect(transport).toHaveBeenCalledTimes(2);
	});

	it.each([
		"https://evil.example/device?user_code=ABCD-1234",
		`${baseURL}/device?device_code=${deviceCode}`,
		`${baseURL}/device?user_code=DIFFERENT`,
		`${baseURL}/device#fragment`,
	])("rejects unsafe verification URI %s before printing it", async (verification_uri_complete) => {
		const transport = vi
			.fn<typeof fetch>()
			.mockResolvedValueOnce(json({ ...approval, verification_uri_complete }));
		const notify = vi.fn();
		await expect(
			loginDevice({ fetch: transport, notify, ...clock(), credentialsFile }),
		).rejects.toThrow("verification");
		expect(notify).not.toHaveBeenCalled();
		expect(transport).toHaveBeenCalledTimes(1);
	});

	it("refuses a raw access token without an issued session cookie", async () => {
		const transport = vi
			.fn<typeof fetch>()
			.mockResolvedValueOnce(json(approval))
			.mockResolvedValueOnce(json(token));
		await expect(
			loginDevice({
				fetch: transport,
				notify: vi.fn(),
				...clock(),
				credentialsFile,
			}),
		).rejects.toThrow("session cookie");
		expect(transport).toHaveBeenCalledTimes(2);
		expect(await loadCredentials(baseURL, credentialsFile)).toBeUndefined();
	});

	it("does not save a returned cookie when root management admission fails", async () => {
		const transport = vi
			.fn<typeof fetch>()
			.mockResolvedValueOnce(json(approval))
			.mockResolvedValueOnce(
				json(token, 200, {
					"set-cookie":
						"__Secure-better-auth.session_token=partial.signature; Path=/",
				}),
			)
			.mockResolvedValueOnce(json({ secret: accessToken }, 403));
		await expect(
			loginDevice({
				fetch: transport,
				notify: vi.fn(),
				...clock(),
				credentialsFile,
			}),
		).rejects.toThrow("HTTP 403");
		expect(await loadCredentials(baseURL, credentialsFile)).toBeUndefined();
	});

	it.each([
		"totp",
		"recovery",
	])("completes the required %s challenge after device approval without asking for a password", async (method) => {
		const pending = new Headers({ "Content-Type": "application/json" });
		pending.append(
			"set-cookie",
			"__Secure-better-auth.session_token=; Max-Age=0; Path=/",
		);
		pending.append(
			"set-cookie",
			"__Secure-better-auth.two_factor=challenge.signed; Path=/; HttpOnly; Secure",
		);
		const completed = new Headers({ "Content-Type": "application/json" });
		completed.append(
			"set-cookie",
			"__Secure-better-auth.two_factor=; Max-Age=0; Path=/",
		);
		completed.append(
			"set-cookie",
			"__Secure-better-auth.session_token=completed.signature; Path=/; HttpOnly; Secure",
		);
		const transport = vi
			.fn<typeof fetch>()
			.mockResolvedValueOnce(json(approval))
			.mockResolvedValueOnce(
				new Response(
					JSON.stringify({
						twoFactorRedirect: true,
						twoFactorMethods: ["totp"],
					}),
					{ headers: pending },
				),
			)
			.mockResolvedValueOnce(
				new Response(
					JSON.stringify({ token: accessToken, user: { id: "root" } }),
					{ headers: completed },
				),
			)
			.mockResolvedValueOnce(json({ workspaces: [] }));
		const prompt = vi
			.fn()
			.mockResolvedValueOnce(method)
			.mockResolvedValueOnce("123456");
		await loginDevice({
			fetch: transport,
			notify: vi.fn(),
			prompt,
			...clock(),
			credentialsFile,
		});
		expect(prompt.mock.calls).toEqual([
			[
				"MFA method: press Enter for authenticator, or type recovery (code comes next): ",
				true,
			],
			[
				method === "recovery"
					? "Recovery code (used once): "
					: "Authenticator code: ",
				true,
			],
		]);
		const [url, init] = transport.mock.calls[2]!;
		expect(new URL(String(url)).pathname).toBe(
			`/api/auth/two-factor/${method === "recovery" ? "verify-backup-code" : "verify-totp"}`,
		);
		expect(new Headers(init?.headers).get("cookie")).toBe(
			"__Secure-better-auth.two_factor=challenge.signed",
		);
		expect(new Headers(init?.headers).get("origin")).toBe(baseURL);
		expect(new Headers(init?.headers).has("authorization")).toBe(false);
		expect(JSON.parse(String(init?.body))).toEqual({
			code: "123456",
			trustDevice: false,
		});
		expect(await loadCredentials(baseURL, credentialsFile)).toBe(
			"__Secure-better-auth.session_token=completed.signature",
		);
		expect(await readFile(credentialsFile, "utf8")).not.toContain(
			"challenge.signed",
		);
		expect(await readFile(credentialsFile, "utf8")).not.toContain(accessToken);
		expect(
			transport.mock.calls.filter(
				([target]) =>
					new URL(String(target)).pathname === "/api/auth/device/token",
			),
		).toHaveLength(1);
	});

	it("does not repeat token redemption or save the partial challenge when MFA fails", async () => {
		const transport = vi
			.fn<typeof fetch>()
			.mockResolvedValueOnce(json(approval))
			.mockResolvedValueOnce(
				json({ twoFactorRedirect: true, twoFactorMethods: ["totp"] }, 200, {
					"set-cookie":
						"__Secure-better-auth.two_factor=challenge.signed; Path=/",
				}),
			)
			.mockResolvedValueOnce(json({ message: accessToken }, 401));
		const prompt = vi
			.fn()
			.mockResolvedValueOnce("totp")
			.mockResolvedValueOnce("000000");
		await expect(
			loginDevice({
				fetch: transport,
				notify: vi.fn(),
				prompt,
				...clock(),
				credentialsFile,
			}),
		).rejects.toThrow("Start a new device login");
		expect(transport).toHaveBeenCalledTimes(3);
		expect(await loadCredentials(baseURL, credentialsFile)).toBeUndefined();
	});

	it("requires an issued completed session after MFA rather than persisting a challenge cookie", async () => {
		const transport = vi
			.fn<typeof fetch>()
			.mockResolvedValueOnce(json(approval))
			.mockResolvedValueOnce(
				json({ twoFactorRedirect: true }, 200, {
					"set-cookie":
						"__Secure-better-auth.two_factor=challenge.signed; Path=/",
				}),
			)
			.mockResolvedValueOnce(json({ user: { id: "root" } }));
		const prompt = vi
			.fn()
			.mockResolvedValueOnce("totp")
			.mockResolvedValueOnce("123456");
		await expect(
			loginDevice({
				fetch: transport,
				notify: vi.fn(),
				prompt,
				...clock(),
				credentialsFile,
			}),
		).rejects.toThrow("session cookie");
		expect(transport).toHaveBeenCalledTimes(3);
		expect(await loadCredentials(baseURL, credentialsFile)).toBeUndefined();
	});

	it("does not prompt for MFA when the approval response lacks its signed challenge cookie", async () => {
		const transport = vi
			.fn<typeof fetch>()
			.mockResolvedValueOnce(json(approval))
			.mockResolvedValueOnce(
				json({ twoFactorRedirect: true, twoFactorMethods: ["totp"] }),
			);
		const prompt = vi.fn();
		await expect(
			loginDevice({
				fetch: transport,
				notify: vi.fn(),
				prompt,
				...clock(),
				credentialsFile,
			}),
		).rejects.toThrow("challenge cookie");
		expect(prompt).not.toHaveBeenCalled();
		expect(await loadCredentials(baseURL, credentialsFile)).toBeUndefined();
	});

	it("refuses an active session while MFA is pending rather than forwarding it to verification", async () => {
		const headers = new Headers({ "Content-Type": "application/json" });
		headers.append(
			"set-cookie",
			"__Secure-better-auth.two_factor=challenge.signed; Path=/",
		);
		headers.append(
			"set-cookie",
			"__Secure-better-auth.session_token=unfinished.signature; Path=/",
		);
		const transport = vi
			.fn<typeof fetch>()
			.mockResolvedValueOnce(json(approval))
			.mockResolvedValueOnce(
				new Response(JSON.stringify({ twoFactorRedirect: true }), { headers }),
			);
		const prompt = vi.fn();
		await expect(
			loginDevice({
				fetch: transport,
				notify: vi.fn(),
				prompt,
				...clock(),
				credentialsFile,
			}),
		).rejects.toThrow("before its required MFA challenge");
		expect(prompt).not.toHaveBeenCalled();
		expect(transport).toHaveBeenCalledTimes(2);
		expect(await loadCredentials(baseURL, credentialsFile)).toBeUndefined();
	});

	it("does not disclose a failed prompt's details or save its MFA challenge", async () => {
		const transport = vi
			.fn<typeof fetch>()
			.mockResolvedValueOnce(json(approval))
			.mockResolvedValueOnce(
				json({ twoFactorRedirect: true }, 200, {
					"set-cookie":
						"__Secure-better-auth.two_factor=challenge.signed; Path=/",
				}),
			);
		const prompt = vi
			.fn()
			.mockRejectedValue(new Error(`Unexpected secret: ${accessToken}`));
		try {
			await loginDevice({
				fetch: transport,
				notify: vi.fn(),
				prompt,
				...clock(),
				credentialsFile,
			});
			throw new Error("Expected failure");
		} catch (failure) {
			expect(publicErrorMessage(failure)).toContain("Start a new device login");
			expect(String(failure)).not.toContain(accessToken);
		}
		expect(transport).toHaveBeenCalledTimes(2);
		expect(await loadCredentials(baseURL, credentialsFile)).toBeUndefined();
	});

	it("leaves the native MFA challenge expiry to the service after the device grant is redeemed", async () => {
		const timing = clock();
		const transport = vi
			.fn<typeof fetch>()
			.mockResolvedValueOnce(json({ ...approval, expires_in: 8 }))
			.mockResolvedValueOnce(
				json({ twoFactorRedirect: true }, 200, {
					"set-cookie":
						"__Secure-better-auth.two_factor=challenge.signed; Path=/",
				}),
			)
			.mockResolvedValueOnce(
				json({ user: { id: "root" } }, 200, {
					"set-cookie":
						"__Secure-better-auth.session_token=completed.signature; Path=/",
				}),
			)
			.mockResolvedValueOnce(json({ workspaces: [] }));
		const prompt = vi
			.fn()
			.mockResolvedValueOnce("totp")
			.mockImplementationOnce(async () => {
				await timing.sleep(10000);
				return "123456";
			});
		await loginDevice({
			fetch: transport,
			notify: vi.fn(),
			prompt,
			...timing,
			credentialsFile,
		});
		expect(await loadCredentials(baseURL, credentialsFile)).toContain(
			"completed.signature",
		);
	});

	it("rejects malformed and oversized protocol responses without disclosing them", async () => {
		for (const response of [
			json({ ...approval, interval: 0 }),
			json({ ...approval, expires_in: 0 }),
			json({ ...approval, extra: accessToken }),
			new Response("secret=" + accessToken, {
				status: 500,
				headers: { "Content-Type": "application/json" },
			}),
			json({ data: "x".repeat(20000) }),
		]) {
			const transport = vi.fn<typeof fetch>().mockResolvedValueOnce(response);
			const notify = vi.fn();
			await expect(
				loginDevice({ fetch: transport, notify, ...clock(), credentialsFile }),
			).rejects.toThrow();
			expect(notify).not.toHaveBeenCalled();
			expect(transport).toHaveBeenCalledTimes(1);
		}
	});

	it("can cancel while awaiting approval and leaves no saved session", async () => {
		const abort = new AbortController();
		const transport = vi
			.fn<typeof fetch>()
			.mockResolvedValueOnce(json(approval));
		await expect(
			loginDevice({
				fetch: transport,
				notify: vi.fn(),
				now: () => 100000,
				sleep: async () => {
					abort.abort();
				},
				signal: abort.signal,
				credentialsFile,
			}),
		).rejects.toThrow("cancelled");
		expect(transport).toHaveBeenCalledTimes(1);
		expect(await loadCredentials(baseURL, credentialsFile)).toBeUndefined();
	});

	it("times out a stalled protocol response with a controlled error", async () => {
		const transport = vi.fn<typeof fetch>().mockImplementation(
			async (_url, init) =>
				new Response(
					new ReadableStream<Uint8Array>({
						start(controller) {
							init?.signal?.addEventListener("abort", () =>
								controller.error(new Error("unsafe transport detail")),
							);
						},
					}),
					{ headers: { "Content-Type": "application/json" } },
				),
		);
		await expect(
			loginDevice({
				fetch: transport,
				notify: vi.fn(),
				timeoutMs: 5,
				...clock(),
				credentialsFile,
			}),
		).rejects.toThrow("timed out");
		expect(await loadCredentials(baseURL, credentialsFile)).toBeUndefined();
	});
});

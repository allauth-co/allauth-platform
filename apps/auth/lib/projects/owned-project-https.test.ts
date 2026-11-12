import { EventEmitter } from "node:events";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
	fetchPublicProjectHttps,
	ProjectHttpsResponseTooLarge,
	publicProjectHttpsURL,
	UnsafeProjectHttpsTarget,
} from "./owned-project-https";

const { lookup, https } = vi.hoisted(() => ({
	lookup: vi.fn(),
	https: vi.fn(),
}));
vi.mock("node:dns/promises", () => ({ lookup }));
vi.mock("node:https", () => ({ request: https }));

describe("public project HTTPS transport", () => {
	beforeEach(() => {
		vi.resetAllMocks();
	});

	it("rejects a nonpublic address or mixed DNS answers before connecting", async () => {
		expect(() =>
			publicProjectHttpsURL("https://127.0.0.1/logout", true),
		).toThrow();
		expect(() =>
			publicProjectHttpsURL("https://metadata.google.internal./logout", true),
		).toThrow();
		expect(() =>
			publicProjectHttpsURL("https://[::ffff:192.168.0.1]/", true),
		).toThrow();
		lookup.mockResolvedValue([
			{ address: "93.184.216.34", family: 4 },
			{ address: "10.0.0.1", family: 4 },
		]);
		await expect(
			fetchPublicProjectHttps(
				new Request("https://rp.fixture.example/logout"),
				{
					timeoutMs: 1000,
				},
			),
		).rejects.toBeInstanceOf(UnsafeProjectHttpsTarget);
		expect(https).not.toHaveBeenCalled();
	});

	it("pins a DNS result while connecting with the original TLS identity", async () => {
		const resolved = { address: "93.184.216.34", family: 4 };
		lookup.mockResolvedValue([
			resolved,
			{ address: "2606:4700:4700::1111", family: 6 },
		]);
		const destroy = vi.fn();
		https.mockImplementation((url, options, respond) => {
			expect(url.href).toBe("https://rp.fixture.example/logout");
			expect(options.rejectUnauthorized).toBe(true);
			expect(options.agent).toBe(false);
			expect(options.headers).not.toHaveProperty("host");
			const checked = vi.fn();
			options.lookup(url.hostname, { all: true }, checked);
			expect(checked).toHaveBeenCalledWith(null, [resolved]);
			return Object.assign(new EventEmitter(), {
				end(body: Uint8Array) {
					expect(Buffer.from(body).toString()).toBe("logout_token=fixture");
					respond({ statusCode: 204, headers: {}, destroy });
				},
			});
		});
		const response = await fetchPublicProjectHttps(
			new Request("https://rp.fixture.example/logout", {
				method: "POST",
				body: new URLSearchParams({ logout_token: "fixture" }),
			}),
			{ timeoutMs: 1000, headersOnly: true },
		);
		expect(response.status).toBe(204);
		expect(lookup).toHaveBeenCalledWith("rp.fixture.example.", {
			all: true,
			order: "verbatim",
		});
		expect(https).toHaveBeenCalledTimes(1);
		expect(destroy).toHaveBeenCalledOnce();
	});

	it("rejects redirects without opening another request", async () => {
		lookup.mockResolvedValue([{ address: "93.184.216.34", family: 4 }]);
		https.mockImplementation((_url, _options, respond) =>
			Object.assign(new EventEmitter(), {
				end: () =>
					respond({
						statusCode: 302,
						headers: { location: "https://elsewhere.fixture.example" },
						destroy() {},
					}),
			}),
		);
		await expect(
			fetchPublicProjectHttps(
				new Request("https://rp.fixture.example/logout"),
				{
					timeoutMs: 1000,
				},
			),
		).rejects.toBeInstanceOf(UnsafeProjectHttpsTarget);
		expect(https).toHaveBeenCalledTimes(1);
	});

	it.each([
		true,
		false,
	])("bounds the HTTPS response before buffering (declared length: %s)", async (declared) => {
		lookup.mockResolvedValue([{ address: "93.184.216.34", family: 4 }]);
		const destroy = vi.fn();
		https.mockImplementation((_url, _options, respond) =>
			Object.assign(new EventEmitter(), {
				end() {
					const response = Object.assign(new EventEmitter(), {
						statusCode: 200,
						headers: declared ? { "content-length": "65537" } : {},
						destroy(error?: Error) {
							destroy();
							if (error) response.emit("error", error);
						},
					});
					respond(response);
					if (!declared) {
						response.emit("data", Buffer.alloc(65536));
						response.emit("data", Buffer.alloc(1));
					}
				},
			}),
		);
		await expect(
			fetchPublicProjectHttps(new Request("https://rp.fixture.example/keys"), {
				timeoutMs: 1000,
				maximumResponseBytes: 64 * 1024,
			}),
		).rejects.toBeInstanceOf(ProjectHttpsResponseTooLarge);
		expect(destroy).toHaveBeenCalledOnce();
	});
});

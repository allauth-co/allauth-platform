import { APIError } from "better-auth";
import { describe, expect, it, vi } from "vitest";
import type { DirectoryOperation } from "./service-directory-transport";
import { handleServiceDirectoryRequest } from "./service-directory-transport";

const project = { id: "project-a", slug: "fixture-production" };
const first = `aabk_11111111-1111-4111-8111-111111111111_${"a".repeat(43)}`;
const second = `aabk_22222222-2222-4222-8222-222222222222_${"b".repeat(43)}`;
const request = (path = "users", key = first, method = "GET") =>
	new Request(
		`https://allauth.example/api/projects/${project.slug}/auth/service-directory/${path}`,
		{
			method,
			headers: {
				"allauth-backend-key": key,
				cookie: "must-not-be-forwarded=private",
				"allauth-proxy-signature": "untrusted",
			},
		},
	);
const dependencies = () => ({
	authorize: vi.fn(async (_headers: Headers) => {}),
	consume: vi.fn(async (_key: string) => ({ allowed: true, retryAfter: 0 })),
	read: vi.fn(
		async (
			_operation: DirectoryOperation,
			_headers: Headers,
			_query: Record<string, unknown>,
		) => Response.json({ users: [] }),
	),
});
describe("verified backend directory admission", () => {
	it("only bypasses generic HTTP admission after exact-path and scoped-key verification", async () => {
		const d = dependencies();
		for (const [path, key, method] of [
			["users", "", "GET"],
			["users", "bad-key", "GET"],
			["users", first, "POST"],
			["users/other", first, "GET"],
			["../../sign-in/email", first, "GET"],
		])
			expect(
				await handleServiceDirectoryRequest(
					request(path, key, method),
					project,
					d,
				),
			).toBeNull();
		expect(d.authorize).not.toHaveBeenCalled();
		expect(d.consume).not.toHaveBeenCalled();
		expect(d.read).not.toHaveBeenCalled();
		d.authorize.mockRejectedValue(new APIError("UNAUTHORIZED"));
		expect(
			await handleServiceDirectoryRequest(request(), project, d),
		).toBeNull();
		expect(d.consume).not.toHaveBeenCalled();
		expect(d.read).not.toHaveBeenCalled();
	});
	it("isolates buckets by verified credential and immutable project and forwards no browser authority", async () => {
		const d = dependencies();
		await handleServiceDirectoryRequest(
			request("members?userId=selected&limit=100"),
			project,
			d,
		);
		await handleServiceDirectoryRequest(request("users", second), project, d);
		await handleServiceDirectoryRequest(
			new Request(
				"https://allauth.example/api/projects/other-production/auth/service-directory/users",
				{ headers: { "allauth-backend-key": first } },
			),
			{ id: "project-b", slug: "other-production" },
			d,
		);
		const buckets = d.consume.mock.calls.map((call) => String(call[0]));
		expect(new Set(buckets).size).toBe(3);
		expect(
			buckets.every((key) => /^backend-directory:v1:[a-f0-9]{64}$/.test(key)),
		).toBe(true);
		expect(buckets.join()).not.toContain(first);
		const [operation, headers, query] = d.read.mock.calls[0];
		expect(operation).toBe("serviceDirectoryMembers");
		expect([...headers.keys()]).toEqual(["allauth-backend-key"]);
		expect(query).toEqual({ userId: "selected", limit: "100" });
	});
	it("returns bounded retry metadata and fails closed on storage or native failures", async () => {
		const d = dependencies();
		d.consume.mockResolvedValue({ allowed: false, retryAfter: 2 });
		const response = await handleServiceDirectoryRequest(request(), project, d);
		expect(response?.status).toBe(429);
		expect(response?.headers.get("retry-after")).toBe("2");
		expect(await response?.json()).toMatchObject({
			code: "ALLAUTH_DIRECTORY_RATE_LIMITED",
		});
		expect(d.read).not.toHaveBeenCalled();
		d.consume.mockRejectedValue(new Error("private failure"));
		const unavailable = await handleServiceDirectoryRequest(
			request(),
			project,
			d,
		);
		expect(unavailable?.status).toBe(503);
		expect(JSON.stringify(await unavailable?.json())).not.toContain("private");
	});
	it("revalidates revocation on every call without completed authority caching", async () => {
		const d = dependencies();
		expect(
			(await handleServiceDirectoryRequest(request(), project, d))?.status,
		).toBe(200);
		d.authorize.mockRejectedValue(new APIError("UNAUTHORIZED"));
		expect(
			await handleServiceDirectoryRequest(request(), project, d),
		).toBeNull();
		expect(d.read).toHaveBeenCalledOnce();
		expect(d.authorize).toHaveBeenCalledTimes(2);
	});
});

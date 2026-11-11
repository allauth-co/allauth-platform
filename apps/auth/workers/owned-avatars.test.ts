import { describe, expect, it } from "vitest";
import worker from "./brand-assets";
import { signAvatarRequest } from "../lib/avatars/protocol";
const secret = "synthetic-owned-avatar-secret-longer-than-thirty-two",
	path =
		"/avatars/00000000-0000-4000-8000-000000000001/00000000-0000-4000-8000-000000000002/00000000-0000-4000-8000-000000000003/00000000-0000-4000-8000-000000000004.png",
	url = "https://assets.allauth.co" + path;
const bytes = new Uint8Array([
	137,
	80,
	78,
	71,
	13,
	10,
	26,
	10,
	...Array(16).fill(0),
]);
function fixture() {
	const records = new Map<
		string,
		{ bytes: Uint8Array; metadata: Record<string, string> }
	>();
	let delay: (() => Promise<void>) | undefined;
	const object = (key: string) => {
		const row = records.get(key);
		return row
			? {
					body: new Blob([new Uint8Array(row.bytes)]).stream(),
					size: row.bytes.length,
					customMetadata: row.metadata,
					httpEtag: '"synthetic"',
					writeHttpMetadata: (headers: Headers) => {
						headers.set("content-type", "image/png");
						headers.set("cache-control", "public, max-age=31536000, immutable");
					},
				}
			: null;
	};
	const bucket = {
		put: async (
			key: string,
			body: Uint8Array,
			options: { onlyIf?: Headers; customMetadata?: Record<string, string> },
		) => {
			if (options.onlyIf) await delay?.();
			if (options.onlyIf && records.has(key)) return null;
			records.set(key, {
				bytes: new Uint8Array(body),
				metadata: options.customMetadata || {},
			});
			return object(key);
		},
		get: async (key: string) => object(key),
		head: async (key: string) => object(key),
		delete: async (key: string) => {
			records.delete(key);
		},
	} as unknown as R2Bucket;
	return {
		records,
		delayPut(value: () => Promise<void>) {
			delay = value;
		},
		env: {
			OWNED_AVATARS: bucket,
			ALLAUTH_AVATAR_SECRET: secret,
			OWNED_AVATAR_PRIVATE_STORAGE: "true",
			BRAND_ASSETS: {} as R2Bucket,
			ALLAUTH_ASSET_SECRET: "branding-separate-secret-long-enough",
		},
	};
}
async function signed(
	method: "GET" | "PUT" | "DELETE",
	target = url,
	body?: Uint8Array<ArrayBuffer>,
) {
	const request = new Request(target, {
		method,
		...(body ? { body, headers: { "content-type": "image/png" } } : {}),
	});
	return new Request(target, {
		method,
		headers: await signAvatarRequest(request, secret),
		...(body ? { body } : {}),
	});
}
describe("private owned avatar Worker", () => {
	it("refuses missing private storage and malformed/unsigned requests with no-store", async () => {
		const f = fixture();
		for (const response of [
			await worker.fetch(new Request(url), {
				...f.env,
				OWNED_AVATARS: undefined,
			}),
			await worker.fetch(new Request(url, { method: "DELETE" }), f.env),
			await worker.fetch(new Request(url + "?token=secret"), f.env),
			await worker.fetch(new Request(url.replace(".png", ".svg")), f.env),
		]) {
			expect(response.status).toBeGreaterThanOrEqual(400);
			expect(response.headers.get("cache-control")).toContain("no-store");
		}
		expect(f.records.size).toBe(0);
	});
	it("requires a signed lifecycle handshake separate from branding credentials", async () => {
		const f = fixture(),
			target = "https://assets.allauth.co/avatars/capabilities";
		expect((await worker.fetch(new Request(target), f.env)).status).toBe(401);
		const response = await worker.fetch(await signed("GET", target), f.env);
		expect(await response.json()).toEqual({
			profileImageOwnershipAndDeletionProtocol: 1,
		});
		expect(response.headers.get("cache-control")).toContain("no-store");
	});
	it("forces no-store for images and HEAD despite legacy cache metadata or conditional headers", async () => {
		const f = fixture();
		expect(
			(await worker.fetch(await signed("PUT", url, bytes), f.env)).status,
		).toBe(201);
		for (const method of ["GET", "HEAD"]) {
			const response = await worker.fetch(
				new Request(url, {
					method,
					headers: { "if-none-match": '"synthetic"' },
				}),
				f.env,
			);
			expect(response.status).toBe(200);
			expect(response.headers.get("cache-control")).toBe("private, no-store");
		}
	});
	it("erases bytes idempotently and rejects PUT replay, signature tampering and branding deletion", async () => {
		const f = fixture();
		await worker.fetch(await signed("PUT", url, bytes), f.env);
		for (let i = 0; i < 2; i++)
			expect((await worker.fetch(await signed("DELETE"), f.env)).status).toBe(
				204,
			);
		expect(f.records.get(path.slice(1))?.bytes.length).toBe(0);
		expect((await worker.fetch(new Request(url), f.env)).status).toBe(404);
		expect(
			(await worker.fetch(await signed("PUT", url, bytes), f.env)).status,
		).toBe(409);
		const request = await signed("DELETE");
		expect(
			(
				await worker.fetch(
					new Request(url, {
						method: "PUT",
						headers: request.headers,
						body: bytes,
					}),
					f.env,
				)
			).status,
		).toBe(401);
		expect(
			(
				await worker.fetch(
					new Request(url.replace("/avatars/", "/branding/"), {
						method: "DELETE",
						headers: request.headers,
					}),
					f.env,
				)
			).status,
		).toBe(404);
	});
	it("tombstone blocks a delayed conditional PUT from resurrecting erased bytes", async () => {
		const f = fixture();
		let release: () => void = () => {};
		const gate = new Promise<void>((yes) => {
			release = yes;
		});
		f.delayPut(() => gate);
		const put = worker.fetch(await signed("PUT", url, bytes), f.env);
		await new Promise((yes) => setTimeout(yes, 5));
		expect((await worker.fetch(await signed("DELETE"), f.env)).status).toBe(
			204,
		);
		release();
		expect((await put).status).toBe(409);
		expect((await worker.fetch(new Request(url), f.env)).status).toBe(404);
	});
	it("returns fixed no-store failures when storage throws", async () => {
		const f = fixture(),
			bucket = {
				get: async () => {
					throw new Error("private-sentinel");
				},
			} as unknown as R2Bucket;
		const response = await worker.fetch(new Request(url), {
			...f.env,
			OWNED_AVATARS: bucket,
		});
		expect(response.status).toBe(503);
		expect(await response.text()).not.toContain("private-sentinel");
		expect(response.headers.get("cache-control")).toContain("no-store");
	});
	it("never acknowledges erasure when the storage write returns no committed marker", async () => {
		const f = fixture(),
			bucket = { put: async () => null } as unknown as R2Bucket;
		const response = await worker.fetch(await signed("DELETE"), {
			...f.env,
			OWNED_AVATARS: bucket,
		});
		expect(response.status).toBe(503);
		expect(response.headers.get("cache-control")).toContain("no-store");
	});
});

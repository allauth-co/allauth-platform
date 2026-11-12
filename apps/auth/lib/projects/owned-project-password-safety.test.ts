import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createOwnedProjectPasswordSafety } from "./owned-project-password-safety";

const password = "Local-fixture-password-not-sent-to-the-range-service";
const digest = createHash("sha1").update(password).digest("hex").toUpperCase();
const prefix = digest.slice(0, 5);
const suffix = digest.slice(5);

describe("project password breach range", () => {
	it("sends a padded range prefix and rejects a breached password", async () => {
		const check = createOwnedProjectPasswordSafety(async (request) => {
			expect(request.url).toBe(
				`https://api.pwnedpasswords.com/range/${prefix}`,
			);
			expect(request.headers.get("add-padding")).toBe("true");
			expect(request.method).toBe("GET");
			expect(request.body).toBeNull();
			expect(request.redirect).toBe("error");
			return new Response(`${suffix}:123\r\n`);
		});
		expect(await check(password)).toBe("breached");
	});

	it("allows padded zero-count matches and fails closed on unavailable or invalid ranges", async () => {
		const check = (body: string, status = 200) =>
			createOwnedProjectPasswordSafety(
				async () => new Response(body, { status }),
			)(password);
		await expect(check(`${suffix}:0\r\n`)).resolves.toBe("allowed");
		await expect(check(`${suffix}:0`, 503)).resolves.toBe("unavailable");
		await expect(check(`${suffix}:invalid\r\n`)).resolves.toBe("unavailable");
		await expect(check("")).resolves.toBe("unavailable");
		await expect(check(`${suffix}:0\r\n`.repeat(20_000))).resolves.toBe(
			"unavailable",
		);
		const offline = createOwnedProjectPasswordSafety(async () => {
			throw new Error("Fixture outage");
		});
		await expect(offline(password)).resolves.toBe("unavailable");
	});
});

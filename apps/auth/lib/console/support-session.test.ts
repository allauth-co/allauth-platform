import { describe, expect, it, vi } from "vitest";
import { activeSupportSession, endSupportSession, supportSessionHref } from "./support-session";

/** @see apps/auth/INTEGRATION.md#identity-organizations-and-impersonation */
describe("support session navigation and lifecycle", () => {
	it("returns to the selected user in the same workspace and environment", () => {
		const url = new URL(supportSessionHref("store-development", "workspace-a", "user-a"), "https://allauth.invalid");
		expect(url.pathname).toBe("/admin/users");
		expect(Object.fromEntries(url.searchParams)).toEqual({ project: "store-development", workspace: "workspace-a", selected: "user-a" });
		expect(supportSessionHref()).toBe("/account");
	});
	it("only presents a real unexpired impersonation and drops tokens and private fields", () => {
		const now = Date.now();
		const input = { user: { id: "target", email: "target@example.test", name: "Target", privateMetadata: { secret: "private" } }, session: { id: "support-session", impersonatedBy: "actor", expiresAt: new Date(now + 60_000), token: "sensitive" } };
		expect(activeSupportSession(input, now)).toEqual({ id: "support-session", userId: "target", email: "target@example.test", name: "Target", expiresAt: new Date(now + 60_000).toISOString() });
		expect(activeSupportSession(null, now)).toBeNull();
		expect(activeSupportSession({ ...input, session: { ...input.session, impersonatedBy: null } }, now)).toBeNull();
		expect(activeSupportSession({ ...input, session: { ...input.session, expiresAt: new Date(now) } }, now)).toBeNull();
	});
	it("finishes cleanly if the support session expires just before Stop is clicked", async () => {
		const stop = vi.fn().mockResolvedValue({ error: { status: 401, message: "Unauthorized" } });
		const read = vi.fn().mockResolvedValue(null);
		await expect(endSupportSession(stop, read)).resolves.toBeUndefined();
		expect(stop).toHaveBeenCalledOnce();
		expect(read).toHaveBeenCalledOnce();
	});
	it("does not disguise a failed stop while the impersonation is still active", async () => {
		const stop = vi.fn().mockResolvedValue({ error: { status: 403, message: "Request denied" } });
		const read = vi.fn().mockResolvedValue({ id: "still-active" });
		await expect(endSupportSession(stop, read)).rejects.toThrow("Request denied");
	});
});

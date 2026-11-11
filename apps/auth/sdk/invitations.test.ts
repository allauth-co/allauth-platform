import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AllAuthClient } from "./client";
import { acceptInvitationAndEnter } from "./invitations";
import type { InvitationSetup } from "./invitations";

const native = { accept: vi.fn(), list: vi.fn(), setActive: vi.fn(), full: vi.fn(), session: vi.fn() };
const client = { organization: { acceptInvitation: native.accept, list: native.list, setActive: native.setActive, getFullOrganization: native.full }, getSession: native.session } as unknown as AllAuthClient;
beforeEach(() => {
	for (const method of Object.values(native)) method.mockReset();
	native.accept.mockResolvedValue({ data: { invitation: { id: "invite-one", organizationId: "org-one" }, member: { organizationId: "org-one", userId: "invited-user" } }, error: null });
	native.list.mockResolvedValue({ data: [{ id: "org-one", name: "Actual Organisation" }], error: null });
	native.setActive.mockResolvedValue({ error: null });
	native.full.mockResolvedValue({ data: { id: "org-one", name: "Actual Organisation", logo: null }, error: null });
	native.session.mockResolvedValue({ data: { user: { id: "invited-user" }, session: { activeOrganizationId: "org-one" } }, error: null });
});
describe("native invitation completion", () => {
	it("resolves real membership, active session and organisation before host callbacks", async () => {
		const onSelect = vi.fn(); const onOrganizationChange = vi.fn();
		await acceptInvitationAndEnter(client, "invite-one", { onSelect, onOrganizationChange });
		expect(native.accept).toHaveBeenCalledExactlyOnceWith({ invitationId: "invite-one" });
		expect(native.list).toHaveBeenCalledOnce(); expect(native.setActive).toHaveBeenCalledExactlyOnceWith({ organizationId: "org-one" });
		expect(native.session).toHaveBeenCalledTimes(2);
		expect(onSelect).toHaveBeenCalledExactlyOnceWith({ id: "org-one", name: "Actual Organisation", logo: null });
		expect(onOrganizationChange).toHaveBeenCalledExactlyOnceWith({ id: "org-one", name: "Actual Organisation", logo: null }, "select");
	});
	it("preserves native wrong-recipient failures and never notifies a host or selects an organisation", async () => {
		native.accept.mockResolvedValue({ error: { message: "You are not the recipient of the invitation." } });
		const onSelect = vi.fn(); await expect(acceptInvitationAndEnter(client, "invite-one", { onSelect })).rejects.toThrow("not the recipient");
		expect(native.list).not.toHaveBeenCalled(); expect(native.setActive).not.toHaveBeenCalled(); expect(onSelect).not.toHaveBeenCalled();
	});
	it("retries setup after a callback failure without re-accepting or repeating a successful callback", async () => {
		let checkpoint: InvitationSetup | undefined;
		const onSelect = vi.fn(); const onOrganizationChange = vi.fn().mockRejectedValueOnce(new Error("App setup unavailable")).mockResolvedValue(undefined);
		const callbacks = { onSelect, onOrganizationChange, onCheckpoint: (value: InvitationSetup) => { checkpoint = value; } };
		await expect(acceptInvitationAndEnter(client, "invite-one", callbacks)).rejects.toThrow("App setup unavailable");
		await acceptInvitationAndEnter(client, "invite-one", callbacks, checkpoint);
		expect(native.accept).toHaveBeenCalledOnce(); expect(onSelect).toHaveBeenCalledOnce(); expect(onOrganizationChange).toHaveBeenCalledTimes(2);
	});
	it("blocks stale identities and foreign membership from entering a host workspace", async () => {
		const onSelect = vi.fn();
		native.session.mockResolvedValueOnce({ data: { user: { id: "other-user" }, session: {} }, error: null });
		await expect(acceptInvitationAndEnter(client, "invite-one", { onSelect })).rejects.toThrow("invited account");
		expect(native.setActive).not.toHaveBeenCalled(); expect(onSelect).not.toHaveBeenCalled();
		native.list.mockResolvedValue({ data: [], error: null });
		await expect(acceptInvitationAndEnter(client, "invite-one", { onSelect })).rejects.toThrow("membership could not be verified");
		expect(native.setActive).not.toHaveBeenCalled(); expect(onSelect).not.toHaveBeenCalled();
	});
});

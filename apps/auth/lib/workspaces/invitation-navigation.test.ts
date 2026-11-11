import { describe, expect, it } from "vitest";
import { workspaceInvitationHref, workspaceInvitationSignInHref, workspaceInvitationConsoleHref } from "./invitation-navigation";
import { getCallbackURL } from "../shared";
import { localNavigation } from "../../components/better-auth-ui/lib/navigation";

/** @see https://allauth.co/admin/workspaces?tab=team */
describe("workspace invitation email continuation", () => {
	it("preserves the workspace invitation through sign-in without using native organization invitations", () => {
		const id = "invite-fixture";
		expect(workspaceInvitationHref(id)).toBe("/accept-workspace-invitation/invite-fixture");
		const signIn = new URL(workspaceInvitationSignInHref(id), "https://allauth.co");
		expect(signIn.pathname).toBe("/sign-in");
		expect(signIn.searchParams.get("callbackUrl")).toBe(workspaceInvitationConsoleHref(id));
		expect(workspaceInvitationConsoleHref(id)).toBe("/admin/workspaces?tab=team&invitation=invite-fixture");
		expect(getCallbackURL(signIn.searchParams)).toBe(workspaceInvitationConsoleHref(id));
		for (const path of ["/sign-up", "/verify-email", "/two-factor"])
			expect(new URL(localNavigation(path, signIn.origin, signIn.searchParams)!, signIn.origin).searchParams.get("callbackUrl")).toBe(workspaceInvitationConsoleHref(id));
	});
	it("encodes the invitation lookup key rather than treating it as a URL", () => {
		expect(workspaceInvitationHref("/unexpected?value=#fragment")).toBe("/accept-workspace-invitation/%2Funexpected%3Fvalue%3D%23fragment");
		expect(new URL(workspaceInvitationSignInHref("//elsewhere.example"), "https://allauth.co").origin).toBe("https://allauth.co");
	});
});

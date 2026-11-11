import { managementHref } from "@/components/control/helpers";

export interface SupportSession {
	id: string;
	userId: string;
	email: string;
	name: string;
	expiresAt: string;
}

/** Preserve the selected scope after starting support; platform impersonation uses the account portal. */
export function supportSessionHref(project?: string, workspace?: string, userId?: string): string {
	if (!project) return "/account";
	return managementHref(`/admin/users${userId ? `?selected=${encodeURIComponent(userId)}` : ""}`, project, workspace);
}

/** Cache only the display fields of a live native impersonation session. */
export function activeSupportSession(
	current: {
		user: { id: string; email: string; name: string };
		session: { id: string; expiresAt: Date | string; impersonatedBy?: string | null };
	} | null | undefined,
	now = Date.now(),
): SupportSession | null {
	if (!current?.session.impersonatedBy) return null;
	const expiresAt = new Date(current.session.expiresAt);
	if (!(expiresAt.getTime() > now)) return null;
	return { id: current.session.id, userId: current.user.id, email: current.user.email, name: current.user.name, expiresAt: expiresAt.toISOString() };
}

/** An expired or already-ended support session is a completed stop, verified by a fresh read. */
export async function endSupportSession(
	stop: () => Promise<{ error?: { message?: string } | null }>,
	read: () => Promise<unknown | null>,
): Promise<void> {
	const result = await stop();
	if (result.error && await read() !== null)
		throw new Error(result.error.message || "Unable to end the support session.");
}

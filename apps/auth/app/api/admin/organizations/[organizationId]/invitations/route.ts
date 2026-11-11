import { apiRoute, json, requireSameOrigin } from "@/lib/api";
import { authOrigin, setting } from "@/lib/configuration";
import { consoleBody, consoleDatabase, requireConsoleAdministrator } from "@/lib/console/database";
import { changeConsoleInvitation, listConsoleOrganizationInvitations } from "@/lib/console/organizations";
import { reactInvitationEmail } from "@/lib/email/invitation";
import { emailConfigured, sendAuthEmail } from "@/lib/email/send";
import { projectInstance } from "@/lib/projects/runtime";
import { readApplicationBranding } from "@/lib/branding/repository";
export const POST = (request: Request, context: { params: Promise<{ organizationId: string }> }) => apiRoute(request, async (instance, env) => {
	requireSameOrigin(request, env); const actor = await requireConsoleAdministrator(instance, request.headers);
	const emailEnv = { EMAIL: env.EMAIL, EMAIL_FROM: setting(env, "EMAIL_FROM"), CLOUDFLARE_ACCOUNT_ID: setting(env, "CLOUDFLARE_ACCOUNT_ID"), CLOUDFLARE_EMAIL_API_TOKEN: setting(env, "CLOUDFLARE_EMAIL_API_TOKEN") };
	const body = await consoleBody(request);
	if (body && typeof body === "object" && "action" in body && body.action === "send" && !emailConfigured(emailEnv)) return json({ error: "Configure Cloudflare email before sending invitations." }, 409);
	const result = await changeConsoleInvitation(await consoleDatabase(instance), (await context.params).organizationId, body, actor.user.id);
	if (!result.invitation || !result.organization || !result.inviter) return json(result);
	const realm = projectInstance(instance)?.project;
	const inviteLink = realm ? `${realm.primaryOrigin}/account?invitation=${encodeURIComponent(result.invitation.id)}` : `${authOrigin(env)}/accept-invitation/${encodeURIComponent(result.invitation.id)}`;
	try { const branding = realm ? await readApplicationBranding(realm.id, env) : undefined; await sendAuthEmail(emailEnv, { to: result.invitation.email, fromName: branding?.name || "AllAuth", subject: `You've been invited to ${String(result.organization.name)} on ${branding?.name || "AllAuth"}`, react: reactInvitationEmail({ branding, username: result.invitation.email, invitedByUsername: result.inviter.name, invitedByEmail: result.inviter.email, teamName: String(result.organization.name), inviteLink }) }); }
	catch { return json({ error: "The invitation was saved but email delivery failed. Cancel it and try again.", invitation: result.invitation, emailAccepted: false }, 502); }
	return json({ invitation: result.invitation, emailAccepted: true }, 201);
});

export const GET = (request: Request, context: { params: Promise<{ organizationId: string }> }) => apiRoute(request, async (instance) => {
	await requireConsoleAdministrator(instance, request.headers);
	return json(await listConsoleOrganizationInvitations(await consoleDatabase(instance), (await context.params).organizationId, Object.fromEntries(new URL(request.url).searchParams)));
});

import {
	controlSecurityManagementRepository,
	invalidSecurityRuleMessage,
	securityRuleAddInput,
	securityRuleRemoveInput,
	securityUpdateInput,
} from "../control/security-management";
import { canonicalIP } from "../control/security-policy";
import type { ControlEventInput, ControlPrincipal } from "../control/types";
import { accountLinkJson } from "./owned-project-account-links";
import { lockOwnedProjectWorkspaceAdministrator } from "./owned-project-admin-authority";
import type { createProjectEngineStore } from "./owned-project-engine-store";
import { admitOwnedProjectNativeRoute } from "./owned-project-native-admission";
import type { Project } from "./registry";

const reportPath = "/control/security";
const mutations = {
	"/control/security/update": securityUpdateInput,
	"/control/security/rules/add": securityRuleAddInput,
	"/control/security/rules/remove": securityRuleRemoveInput,
} as const;
type Mutation = keyof typeof mutations;

const workspaceRequired = "A verified workspace administrator is required.";
const originRequired = "Security changes require a same-origin request.";

/** Apply workspace-admin security policy and rule changes through the selected project store. */
export function createOwnedProjectSecurityManagement(options: {
	store: ReturnType<typeof createProjectEngineStore>;
	project: Pick<Project, "id" | "slug" | "schemaName" | "workspaceId">;
	origin: string;
	basePath: string;
	platformOrigin: string;
	readWorkspacePrincipal(headers: Headers): Promise<ControlPrincipal | null>;
	readBody(request: Request): Promise<unknown>;
	trustedIP(request: Request): string | null;
	newDeviceNotifications: boolean;
}) {
	const { store, project } = options;
	const direct = `/api/projects/${project.slug}/auth`;
	return async (request: Request, path: string) => {
		const read = request.method === "GET" && path === reportPath;
		const mutation =
			request.method === "POST" && Object.hasOwn(mutations, path)
				? (path as Mutation)
				: undefined;
		if (!read && !mutation) return null;
		const url = new URL(request.url);
		if (
			options.basePath !== direct ||
			options.origin !== options.platformOrigin ||
			url.origin !== options.platformOrigin ||
			url.pathname !== direct + path ||
			request.headers.has("authorization")
		)
			return accountLinkJson({ message: workspaceRequired }, 403);
		const actor = await options.readWorkspacePrincipal(request.headers);
		if (
			!actor ||
			actor.session.userId !== actor.user.id ||
			actor.session.impersonatedBy ||
			!actor.user.emailVerified ||
			actor.user.banned
		)
			return accountLinkJson({ message: workspaceRequired }, 403);
		if (
			mutation &&
			(request.headers.get("origin") !== options.platformOrigin ||
				request.headers.get("sec-fetch-site") === "cross-site")
		)
			return accountLinkJson({ message: originRequired }, 403);

		const input = mutation ? await options.readBody(request) : undefined;
		const parsed = mutation && mutations[mutation].safeParse(input);
		if (parsed && !parsed.success)
			return accountLinkJson(
				{
					code: "VALIDATION_ERROR",
					message: parsed.error.issues
						.map(
							({ path, message }) =>
								`[body${path.length ? `.${path.join(".")}` : ""}] ${message}`,
						)
						.join("; "),
				},
				400,
			);

		const ip = canonicalIP(options.trustedIP(request));
		return store.transaction(async (client) => {
			if (
				!(await lockOwnedProjectWorkspaceAdministrator(client, project, actor))
			)
				return accountLinkJson({ message: workspaceRequired }, 403);
			if (ip) {
				const limited = await admitOwnedProjectNativeRoute(client, ip, path, {
					max: 100,
					windowMs: 60_000,
				});
				if (limited) return limited;
			}
			const management = controlSecurityManagementRepository(client);
			const record = (
				event: Pick<ControlEventInput, "type" | "targetId" | "metadata">,
			) =>
				store.recordEvent(client, {
					...event,
					outcome: "success",
					actorId: actor.user.id,
					ipAddress: ip ?? undefined,
					userAgent: request.headers.get("user-agent") ?? undefined,
				});
			if (!parsed)
				return accountLinkJson(
					await management.report({
						newDeviceNotifications: options.newDeviceNotifications,
						// The legacy platform has no separate breached-password plug-in.
						breachedPasswords: false,
					}),
				);
			const body = parsed.data;
			if ("policy" in body) {
				const policy = await management.updatePolicy(body.policy);
				await record({
					type: "security.policy.updated",
					metadata: { fields: Object.keys(policy) },
				});
				return accountLinkJson({ policy });
			}
			if ("type" in body) {
				const rule = await management.addRule(body);
				if (!rule)
					return accountLinkJson({ message: invalidSecurityRuleMessage }, 400);
				await record({
					type: "security.rule.added",
					targetId: rule.id,
					metadata: { ruleType: body.type },
				});
				return accountLinkJson({ rule });
			}
			await management.removeRule(body.id);
			await record({ type: "security.rule.removed", targetId: body.id });
			return accountLinkJson({ success: true });
		});
	};
}

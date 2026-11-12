import * as z from "zod";
import { getAuthEnvironment } from "../auth";
import type { AuthEnvironment } from "../configuration";
import { authOrigin, setting } from "../configuration";
import { edgeHeaders, portalHeader } from "../domains/edge";
import { hostedSdkTransportEnabled } from "../domains/hosted-sdk-selection";
import {
	resolveHostedBinding,
	withPortalHeadersEngine,
} from "../domains/hosting";
import { listStoredActiveProjectHostnames } from "../domains/repository";
import { domainDefaults } from "../domains/validation";
import { selectedNativePasskeys } from "../project-native-passkeys";
import { projectEnginePreparedForWriter } from "../projects/project-engine-internal-selection";
import { projectWriterLease } from "../projects/project-engine-internal-writer";
import { projectWriterUnavailable } from "../projects/project-engine-unavailable";
import type { Project } from "../projects/registry";
import { getProject, projectRegistryPool } from "../projects/registry";
import { withResolvedProjectAuthEngine } from "../projects/runtime";
import { deviceReviewPath } from "./device";
import { freshFeatureSession } from "./helpers";

export const hostedDeviceReviewPath = "/account/device";

const deviceSession = z.object({
	user: z.object({
		id: z.string().min(1),
		emailVerified: z.boolean(),
		banned: z.boolean().nullish(),
		isAnonymous: z.boolean().nullish(),
	}),
	session: z.object({
		userId: z.string().min(1),
		createdAt: z.string(),
		expiresAt: z.string(),
		impersonatedBy: z.string().nullish(),
	}),
});

export function devicePageCode(code: string | string[] | undefined) {
	return typeof code === "string" && code.length <= 200 ? code : "";
}

/** Use the selected realm's live cookie without renewing it or reviewing the code. */
async function freshDirectProjectSession(
	project: Project,
	env: AuthEnvironment,
	input: Headers,
	basePath: string,
) {
	const name = `allauth_project_${project.slug}.session_token`;
	const cookies = (input.get("cookie") ?? "")
		.split(";")
		.map((pair) => pair.trim())
		.filter((pair) => {
			const cookieName = pair.split("=", 1)[0];
			return cookieName === name || cookieName === `__Secure-${name}`;
		});
	if (!cookies.length) return false;
	return withResolvedProjectAuthEngine(
		project,
		async ({ engine }) => {
			const origin = authOrigin(env);
			const response = await engine.readSession(
				new Request(
					`${origin}${basePath}/get-session?disableRefresh=true&disableCookieCache=true`,
					{ headers: { cookie: cookies.join("; ") } },
				),
			);
			if (!response.ok) return false;
			const current = deviceSession.safeParse(await response.json());
			return (
				current.success &&
				current.data.session.userId === current.data.user.id &&
				!current.data.user.isAnonymous &&
				freshFeatureSession(current.data)
			);
		},
		env,
	);
}

async function verifiedAccountsOrigin(project: Project, env: AuthEnvironment) {
	if (
		setting(env, "CLOUDFLARE_SAAS_READY") !== "true" ||
		setting(env, "ALLAUTH_EDGE_SECRET").length < 32
	)
		return;
	const managed = new URL(domainDefaults(project.slug, env).accounts);
	const candidates = [managed.hostname];
	if (setting(env, "ALLAUTH_PROJECT_NATIVE_PASSKEYS")) {
		const custom = await listStoredActiveProjectHostnames(
			project.id,
			projectRegistryPool(env),
		);
		for (const { hostname, kind } of custom) {
			if (
				kind === "accounts" &&
				selectedNativePasskeys(env, project, `https://${hostname}`).enabled
			) {
				candidates.unshift(hostname);
				break;
			}
		}
	}
	for (const hostname of candidates) {
		const binding = await resolveHostedBinding(hostname, env);
		if (
			binding?.kind === "accounts" &&
			binding.hostname === hostname &&
			binding.project.id === project.id &&
			binding.project.schemaName === project.schemaName &&
			binding.project.workspaceId === project.workspaceId &&
			binding.project.environment === project.environment
		)
			return `https://${hostname}`;
	}
}

/** Preserve the public device URL while preferring a verified project browser. */
export async function projectDevicePage(
	slug: string,
	code: string,
	headers: Headers,
) {
	const env = await getAuthEnvironment();
	const project = await getProject(slug, env);
	const basePath = `/api/projects/${project.slug}/auth`;
	if (!hostedSdkTransportEnabled(env, project, "accounts")) return { basePath };

	const writer = await projectWriterLease(project, env)?.read();
	if (
		writer?.writer === "allauth" &&
		!projectEnginePreparedForWriter(env, project, {
			revision: writer.revision,
			preparing: false,
		})
	)
		throw projectWriterUnavailable();
	const accounts = await verifiedAccountsOrigin(project, env);
	if (!accounts) return { basePath };

	const reauthentication = {
		signInURL: `${accounts}/sign-in`,
		returnPath: hostedDeviceReviewPath,
	} as const;
	if (
		writer?.writer === "allauth" &&
		!(await freshDirectProjectSession(project, env, headers, basePath))
	)
		return {
			basePath,
			reauthentication,
			redirectTo: new URL(
				deviceReviewPath(code, undefined, hostedDeviceReviewPath),
				accounts,
			).href,
		};
	return { basePath, reauthentication };
}

/** A hosted device browser inherits its realm only from the verified accounts hostname. */
export async function hostedDeviceProject(headers: Headers) {
	if (!headers.has(portalHeader) && !edgeHeaders.some((name) => headers.has(name)))
		return;
	return withPortalHeadersEngine(headers, async (_engine, _bound, binding, env) =>
		binding?.kind === "accounts" &&
		hostedSdkTransportEnabled(env, binding.project, binding.kind)
			? binding.project.slug
			: undefined,
	);
}

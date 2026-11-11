import { APIError } from "better-auth";
import * as z from "zod";
import type { Pool } from "pg";
import { withAuth } from "../auth";
import { authConfiguration, authOrigin } from "../configuration";
import { authPolicyRepository } from "../auth-policy/storage";
import { withProjectSettingsWrite } from "../auth-policy/serialization";
import { domainDefaults } from "../domains/validation";
import { getProject, projectRegistryPool } from "../projects/registry";
import { projectAdministrator, requireWorkspaceActor, requireWorkspacePrincipal } from "../workspaces/authorization";
import { googleProviderHandler } from "./api";
import type { GoogleProviderDependencies } from "./api";
import { googleProviderRepository } from "./repository";
import { readProjectAppleProvider } from "./apple";
import { readProjectMicrosoftProvider } from "./microsoft";

/** Selected-environment provider administration never accepts tenant-only roles or bearer credentials. */
export async function googleProviderRoute(request: Request, slug: string): Promise<Response> {
	try {
		return await withAuth(async (instance, env) => {
			const pool = projectRegistryPool(env);
			const sharedGoogle = authConfiguration(env).google;
			const dependencies = (database: Pick<Pool, "query">): GoogleProviderDependencies => {
				const repository = googleProviderRepository(database, env);
				return {
				origin: authOrigin(env), brokerGoogleEnabled: sharedGoogle,
				project: (selected) => getProject(selected, env),
				authorize: async (headers, project) => projectAdministrator(project, await requireWorkspacePrincipal(instance, headers), env),
				read: repository.read,
				update: (project, input, actorId) => repository.update(project, input, actorId),
				canDisableGoogle: async (project) => sharedGoogle || Boolean(readProjectAppleProvider(env, project.slug)) || Boolean(readProjectMicrosoftProvider(env, project.slug)) || (await authPolicyRepository(database).read(project.id)).policy.emailAndPasswordEnabled,
				serializeWrite: (project, actor, work) => withProjectSettingsWrite(pool, project.id, async (transaction) => {
					await requireWorkspaceActor(actor, project.workspaceId, env, { database: transaction });
					return work(dependencies(transaction));
				}),
				callbackUrls: async (project) => {
					const hosted = (await database.query<{ hostname: string }>('SELECT h.hostname FROM public."allauthCustomHostname" h JOIN public."allauthDomainPair" d ON d.id=h."pairId" WHERE h."projectId"=$1 AND h.kind=\'accounts\' AND d.deleting=false AND (SELECT COUNT(*) FROM public."allauthCustomHostname" s WHERE s."pairId"=d.id AND s."ownershipVerifiedAt" IS NOT NULL AND s."providerStatus"=\'active\' AND s."sslStatus"=\'active\' AND s."routingVerifiedAt" IS NOT NULL AND s."lastIssue" IS NULL)=2 ORDER BY h.hostname', [project.id])).rows;
					return [...new Set([`${project.primaryOrigin}/api/allauth/callback/google`, `${domainDefaults(project.slug, env).accounts}/api/auth/callback/google`, ...hosted.map((host) => `https://${host.hostname}/api/auth/callback/google`)])];
				},
				};
			};
			return googleProviderHandler(dependencies(pool))(request, slug);
		});
	} catch (error) {
		const status = error instanceof APIError ? error.statusCode : error instanceof z.ZodError ? 400 : 500;
		return Response.json({ error: error instanceof APIError ? error.body?.message || "The request is not permitted." : status === 400 ? "The Google settings document contains invalid fields." : "Google provider settings could not be loaded or saved." }, { status, headers: { "cache-control": "no-store" } });
	}
}

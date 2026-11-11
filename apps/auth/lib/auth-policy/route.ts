import { APIError } from "better-auth";
import type { Pool } from "pg";
import * as z from "zod";
import { withAuth } from "../auth";
import {
	authConfiguration,
	authOrigin,
	projectEmailEnvironment,
} from "../configuration";
import { emailConfigured } from "../email/send";
import { readProjectAppleProvider } from "../project-providers/apple";
import { readProjectMicrosoftProvider } from "../project-providers/microsoft";
import { googleProviderRepository } from "../project-providers/repository";
import { getProject, projectRegistryPool } from "../projects/registry";
import { checkedProjectSchema } from "../projects/validation";
import {
	projectAdministrator,
	requireWorkspaceActor,
	requireWorkspacePrincipal,
} from "../workspaces/authorization";
import type { ConfigurationDependencies } from "./api";
import { configurationHandler } from "./api";
import { withProjectSettingsWrite } from "./serialization";
import { authPolicyRepository } from "./storage";

/** Reads and updates the selected scope while retaining authoritative platform administration. */
export async function authConfigurationRoute(
	request: Request,
): Promise<Response> {
	try {
		return await withAuth(async (instance, env) => {
			const pool = projectRegistryPool(env);
			const dependencies = (
				database: Pick<Pool, "query">,
			): ConfigurationDependencies => {
				const repository = authPolicyRepository(database);
				return {
					origin: authOrigin(env),
					authorize: async (headers, scope) => {
						const principal = await requireWorkspacePrincipal(
							instance,
							headers,
						);
						return scope.type === "project"
							? projectAdministrator(
									await getProject(scope.slug!, env),
									principal,
									env,
								)
							: principal;
					},
					resolveScope: async (slug) => {
						if (!slug)
							return {
								type: "platform",
								id: "platform",
								name: "AllAuth platform",
								schemaName: "public",
							};
						const project = await getProject(slug, env);
						return {
							type: "project",
							id: project.id,
							name: project.name,
							slug: project.slug,
							schemaName: checkedProjectSchema(project.schemaName),
							origins: project.origins,
							primaryOrigin: project.primaryOrigin,
						};
					},
					read: repository.read,
					update: (id, version, policy, actorId, scope) =>
						repository.update(id, version, policy, actorId, scope.schemaName),
					providers: async (scope) => {
						const available = authConfiguration(env);
						const direct =
							scope.type === "project"
								? await googleProviderRepository(database, env).read(scope.id)
								: null;
						return {
							apple:
								scope.type === "project" &&
								Boolean(readProjectAppleProvider(env, scope.slug!)),
							google:
								available.google ||
								Boolean(
									direct?.enabled &&
										direct.clientId &&
										direct.encryptedClientSecret,
								),
							github: scope.type === "platform" && available.github,
							microsoft:
								scope.type === "platform"
									? available.microsoft
									: Boolean(readProjectMicrosoftProvider(env, scope.slug!)),
							email:
								scope.type === "project"
									? emailConfigured(projectEmailEnvironment(env, scope.slug))
									: available.email,
						};
					},
					unenrolledUsers: async (scope) =>
						Number(
							(
								await database.query<{ total: string }>(
									`SELECT COUNT(*)::text AS total FROM "${scope.schemaName}"."user" WHERE COALESCE(banned,false)=false AND COALESCE("directoryDisabled",false)=false AND (COALESCE("twoFactorEnabled",false)=false OR "emailVerified"=false)`,
								)
							).rows[0].total,
						),
					ownerCanLogin: async (ownerId, policy, available) => {
						const accounts = (
							await database.query<{
								providerId: string;
								password: string | null;
							}>(
								'SELECT "providerId",password FROM public.account WHERE "userId"=$1',
								[ownerId],
							)
						).rows;
						return accounts.some((account) =>
							account.providerId === "credential"
								? policy.emailAndPasswordEnabled && Boolean(account.password)
								: account.providerId === "google"
									? available.google
									: account.providerId === "github"
										? available.github
										: account.providerId === "microsoft" && available.microsoft,
						);
					},
					serializeWrite: async (scope, actor, work) => {
						if (scope.type !== "project") return work(dependencies(database));
						const project = await getProject(scope.slug!, env);
						return withProjectSettingsWrite(
							pool,
							project.id,
							async (transaction) => {
								await requireWorkspaceActor(actor, project.workspaceId, env, {
									database: transaction,
								});
								return work(dependencies(transaction));
							},
						);
					},
				};
			};
			return configurationHandler(dependencies(pool))(request);
		});
	} catch (error) {
		const status =
			error instanceof APIError
				? error.statusCode
				: error instanceof z.ZodError
					? 400
					: 500;
		return Response.json(
			{
				error:
					error instanceof APIError
						? error.body?.message || "The request is not permitted."
						: status === 400
							? "The settings document contains invalid fields."
							: "Settings could not be loaded or saved.",
			},
			{ status, headers: { "cache-control": "no-store" } },
		);
	}
}

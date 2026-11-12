import { createHash } from "node:crypto";
import { APIError } from "better-auth";
import { after } from "next/server";
import type { AuthEnvironment } from "@/lib/configuration";
import { setting } from "@/lib/configuration";
import { createOwnedProjectRuntimeCandidate } from "@/lib/projects/owned-project-runtime-factory";
import type { Project } from "@/lib/projects/registry";
import { projectRegistryPool } from "@/lib/projects/registry";
import type { ProjectEngineBuilder } from "@/lib/projects/runtime";

const uuid = /^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/;
const fixtureDatabase = /^\/allauth_engine_rehearsal_[a-f0-9]{32}$/;
const unavailable = () =>
	new APIError("SERVICE_UNAVAILABLE", {
		message: "The selected project engine rehearsal is unavailable.",
	});

/** This file replaces the no-op selector only in the explicitly built rehearsal image. */
export async function selectRehearsalProjectEngine(
	project: Project,
	env: AuthEnvironment,
): Promise<ProjectEngineBuilder | undefined> {
	const projectId = setting(env, "ALLAUTH_REHEARSAL_PROJECT_ID");
	const workspaceId = setting(env, "ALLAUTH_REHEARSAL_WORKSPACE_ID");
	const nonce = setting(env, "ALLAUTH_REHEARSAL_DATABASE_NONCE");
	if (!projectId && !workspaceId && !nonce) return;
	if (
		!uuid.test(projectId) ||
		!uuid.test(workspaceId) ||
		!/^[a-f0-9]{64}$/.test(nonce)
	)
		throw unavailable();
	if (project.id !== projectId) return;
	const database = URL.parse(setting(env, "DATABASE_URL"));
	if (
		project.environment !== "development" ||
		project.workspaceId !== workspaceId ||
		project.schemaName !== `allauth_project_${projectId.replaceAll("-", "")}` ||
		!database ||
		!["postgres:", "postgresql:"].includes(database.protocol) ||
		!fixtureDatabase.test(database.pathname)
	)
		throw unavailable();

	try {
		const marker = await projectRegistryPool(env).query(
			`SELECT 1 FROM public."allauthEngineRehearsal"
			 WHERE "projectId"=$1 AND "workspaceId"=$2 AND "nonceHash"=$3
			 AND current_database()=$4`,
			[
				projectId,
				workspaceId,
				createHash("sha256").update(nonce).digest("hex"),
				database.pathname.slice(1),
			],
		);
		if (marker.rowCount !== 1) throw unavailable();
	} catch {
		throw unavailable();
	}

	const emailPrefix = `ALLAUTH_PROJECT_${project.slug.replaceAll("-", "_").toUpperCase()}_`;
	const environment: AuthEnvironment = {
		...env,
		EMAIL_PROVIDER: "cloudflare",
		EMAIL_FROM: "security@project-engine-rehearsal.invalid",
		[`${emailPrefix}EMAIL_PROVIDER`]: "cloudflare",
		EMAIL: {
			async send({ to }) {
				if (!to.toLowerCase().endsWith("@project-engine-rehearsal.invalid"))
					throw new Error(
						"Rehearsal mail is restricted to synthetic recipients.",
					);
			},
		},
	};
	return async ({
		database: pool,
		project,
		policy,
		baseURL,
		basePath,
		signingSecret,
		credentialHashSecret,
	}) => {
		const hosted = basePath === "/api/auth";
		return createOwnedProjectRuntimeCandidate({
			database: pool,
			project,
			policy,
			env: environment,
			transport: hosted
				? { kind: "hosted", origin: baseURL }
				: { kind: "direct" },
			signingSecret,
			credentialHashSecret,
			// Normal dispatch verifies the signed edge or application proxy before engine code runs.
			trustedIP: (request) =>
				hosted
					? request.headers.get("x-real-ip")
					: request.headers.has("allauth-proxy-signature")
						? request.headers.get("allauth-proxy-ip")
						: null,
			defer: (work) => after(work),
			async fetchPasswordRange(request) {
				const url = new URL(request.url);
				if (
					url.origin !== "https://api.pwnedpasswords.com" ||
					!/^\/range\/[A-F0-9]{5}$/.test(url.pathname)
				)
					throw new Error("Unexpected password safety request in rehearsal.");
				return new Response(`${"F".repeat(35)}:0\r\n`);
			},
			async postBackchannelLogout() {
				throw new Error(
					"Rehearsal does not send back-channel logout requests.",
				);
			},
		});
	};
}

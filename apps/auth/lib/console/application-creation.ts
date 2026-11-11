import { projectInput } from "../projects/validation";

export type ApplicationEnvironment = "development" | "production";
interface ApplicationInstance {
	applicationId: string;
	workspaceId: string;
	name: string;
	environment: ApplicationEnvironment;
}
export interface ApplicationCreationDraft {
	name: string;
	slug: string;
	primaryOrigin: string;
	origins: string;
	environment: ApplicationEnvironment;
}

/** Offer only the missing counterpart of an existing application's environment. */
export function missingApplicationEnvironment(
	instances: readonly Pick<ApplicationInstance, "environment">[],
): ApplicationEnvironment | null {
	if (!instances.length) return null;
	const present = new Set(instances.map((instance) => instance.environment));
	if (!present.has("development")) return "development";
	if (!present.has("production")) return "production";
	return null;
}

/** Creation always belongs to the selected workspace and an explicit application intent. */
export function applicationCreationInput(
	draft: ApplicationCreationDraft,
	workspaceId: string,
	instances?: readonly ApplicationInstance[],
) {
	if (!workspaceId) throw new Error("Choose a workspace for this application.");
	const application = instances?.[0];
	const missing = instances ? missingApplicationEnvironment(instances) : null;
	if (instances && (!application || !missing))
		throw new Error("This application already has both environments.");
	if (
		instances?.some(
			(instance) =>
				instance.workspaceId !== workspaceId ||
				instance.applicationId !== application?.applicationId,
		)
	)
		throw new Error("Choose an application from this workspace.");
	return projectInput.parse({
		name: application?.name ?? draft.name.trim(),
		slug: draft.slug.trim(),
		primaryOrigin: draft.primaryOrigin.trim().replace(/\/$/, ""),
		origins: [
			...new Set(
				draft.origins
					.split(/\s+/)
					.filter(Boolean)
					.map((value) => value.replace(/\/$/, "")),
			),
		],
		environment: missing ?? draft.environment,
		applicationId: application?.applicationId,
		workspaceId,
	});
}

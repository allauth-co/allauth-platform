import { createHash } from "node:crypto";
import * as z from "zod";
import type { Project } from "./registry";
import { projectOrigin } from "./validation";

export const projectOriginsInput = z.object({
	projectId: z.uuid(), environment: z.enum(["development", "production"]),
	version: z.string().regex(/^[a-f0-9]{64}$/), primaryOrigin: projectOrigin,
	origins: z.array(projectOrigin).min(1).max(10),
}).strict().superRefine((value, context) => {
	if (!value.origins.includes(value.primaryOrigin) || new Set(value.origins).size !== value.origins.length)
		context.addIssue({ code: "custom", message: "Include the primary origin once in the complete allowed origin list." });
	if (value.environment === "production" && value.origins.some((origin) => !origin.startsWith("https:")))
		context.addIssue({ code: "custom", message: "Production origins require HTTPS." });
});
export type ProjectOriginsInput = z.infer<typeof projectOriginsInput>;

/** Origin trust and the RP are independent of transport-secret rotation. */
export function projectOriginFingerprint(project: Pick<Project, "primaryOrigin" | "origins">): string {
	return createHash("sha256").update(JSON.stringify([project.primaryOrigin, [...new Set(project.origins)].sort()])).digest("hex");
}

/** A stored revision prevents overwriting a later change, including a change back to an earlier origin set. */
export function projectOriginsVersion(project: Pick<Project, "id" | "environment" | "primaryOrigin" | "origins" | "updatedAt">): string {
	return createHash("sha256").update(JSON.stringify([project.id, project.environment, projectOriginFingerprint(project), new Date(project.updatedAt).toISOString()])).digest("hex");
}

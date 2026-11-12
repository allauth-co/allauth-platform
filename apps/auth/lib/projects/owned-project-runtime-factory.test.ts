import { Pool } from "pg";
import { describe, expect, it, vi } from "vitest";
import { defaultAuthPolicy } from "../auth-policy/policy";
import { projectEmailAliasVariable } from "../project-email-aliases";
import { createOwnedProjectRuntimeCandidate } from "./owned-project-runtime-factory";
import type { Project } from "./registry";

describe("internal candidate feature admission", () => {
	it.each([
		"direct",
		"hosted",
	] as const)("rejects configured legacy email aliases before opening the %s writer", async (kind) => {
		const slug = "alias-fixture";
		const project: Project = {
			id: "35a18272-5155-4a0e-8fdb-cc74e761734c",
			name: "Alias fixture",
			slug,
			schemaName: "allauth_project_35a1827251554a0e8fdbcc74e761734c",
			primaryOrigin: "https://app.alias-fixture.example",
			origins: ["https://app.alias-fixture.example"],
			applicationId: "alias-fixture",
			environment: "development",
			workspaceId: "00000000-0000-4000-8000-000000000001",
			brokerClientId: "fixture-broker",
			brokerSecret: "fixture-encrypted-value",
			proxyVersion: "fixture-proxy-version",
			createdBy: "fixture-owner",
			createdAt: new Date(0),
			updatedAt: new Date(0),
		};
		const database = new Pool();
		const query = vi.spyOn(database, "query");
		try {
			await expect(
				createOwnedProjectRuntimeCandidate({
					database,
					project,
					policy: defaultAuthPolicy,
					env: {
						ALLAUTH_AUTH_URL: "https://platform.alias-fixture.example",
						EMAIL_PROVIDER: "resend",
						RESEND_API_KEY: "",
						[projectEmailAliasVariable(slug)]:
							'{"reserved@alias-fixture.example":"fixture-user"}',
					},
					transport:
						kind === "hosted"
							? { kind, origin: "https://accounts.alias-fixture.example" }
							: { kind },
					signingSecret: "disposable-project-fixture-signing-secret",
					credentialHashSecret: "disposable-project-fixture-credential-secret",
					trustedIP: () => null,
					defer: () => {},
				}),
			).rejects.toThrow(
				/^Configured project email aliases require the legacy writer\.$/,
			);
			expect(query).not.toHaveBeenCalled();
		} finally {
			await database.end();
		}
	});
});

import { describe, expect, it } from "vitest";
import {
	applicationCreationInput,
	missingApplicationEnvironment,
} from "./application-creation";

const workspace = "12345678-1234-4123-8123-123456789abc";
const applicationId = "22345678-1234-4123-8123-123456789abc";
const draft = {
	name: "New app",
	slug: "new-development",
	primaryOrigin: "https://app.example.com/",
	origins: "https://www.example.com/ https://www.example.com",
	environment: "development" as const,
};
const instance = {
	applicationId,
	workspaceId: workspace,
	name: "Existing app",
	environment: "development" as const,
};

describe("workspace application creation intent", () => {
	it("creates a new application in the explicit workspace with normalized origins", () => {
		expect(applicationCreationInput(draft, workspace)).toEqual({
			name: "New app",
			slug: "new-development",
			primaryOrigin: "https://app.example.com",
			origins: ["https://www.example.com"],
			environment: "development",
			workspaceId: workspace,
			applicationId: undefined,
		});
	});
	it("locks an added instance to the existing application and missing environment", () => {
		expect(
			applicationCreationInput(draft, workspace, [instance]),
		).toMatchObject({
			name: "Existing app",
			applicationId,
			workspaceId: workspace,
			environment: "production",
		});
		expect(
			applicationCreationInput(draft, workspace, [
				{ ...instance, environment: "production" },
			]),
		).toMatchObject({ applicationId, environment: "development" });
	});
	it("never creates an application outside a workspace or mixes workspace/application scopes", () => {
		expect(() => applicationCreationInput(draft, "")).toThrow(
			"Choose a workspace",
		);
		expect(() =>
			applicationCreationInput(draft, "32345678-1234-4123-8123-123456789abc", [
				instance,
			]),
		).toThrow("from this workspace");
		expect(() =>
			applicationCreationInput(draft, workspace, [
				instance,
				{ ...instance, applicationId: "other" },
			]),
		).toThrow("from this workspace");
	});
	it("refuses a third or duplicate environment and never invents an instance for an empty application", () => {
		const both = [
			instance,
			{ ...instance, environment: "production" as const },
		];
		expect(missingApplicationEnvironment(both)).toBeNull();
		expect(missingApplicationEnvironment([])).toBeNull();
		expect(() => applicationCreationInput(draft, workspace, both)).toThrow(
			"both environments",
		);
		expect(() => applicationCreationInput(draft, workspace, [])).toThrow(
			"both environments",
		);
	});
	it("still applies the production HTTPS contract to a missing production environment", () => {
		expect(() =>
			applicationCreationInput(
				{ ...draft, primaryOrigin: "http://localhost:3000" },
				workspace,
				[instance],
			),
		).toThrow("Production environments require HTTPS");
	});
});

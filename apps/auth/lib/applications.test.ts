import { describe, expect, it } from "vitest";
import { publicApplication } from "./applications";

describe("managed application responses", () => {
	it("retains organization, resource and local callback policy from native flattened OAuth metadata", () => {
		const response = publicApplication({ client_id: "test-client", client_name: "Test", allauthOrganizationIds: ["organization-one", 1], allauthResourceURI: "https://api.example.com", allauthAllowLocalhost: true });
		expect(response).toMatchObject({ organizationIds: ["organization-one"], resourceURI: "https://api.example.com", allowLocalhost: true });
	});
	it("retains the same policy from a nested schema record", () => {
		const response = publicApplication({ client_id: "test-client", metadata: { allauthOrganizationIds: ["organization-one"], allauthResourceURI: "https://api.example.com", allauthAllowLocalhost: true } });
		expect(response).toMatchObject({ organizationIds: ["organization-one"], resourceURI: "https://api.example.com", allowLocalhost: true });
	});
	it("uses canonical flattened policy without merging a nested extension", () => {
		const response = publicApplication({ client_id: "test-client", allauthResourceURI: "https://canonical.example.com", metadata: { allauthOrganizationIds: ["nested-organization"], allauthResourceURI: "https://nested.example.com", allauthAllowLocalhost: true } });
		expect(response).toMatchObject({ organizationIds: [], resourceURI: "https://canonical.example.com", allowLocalhost: false });
	});
	it("returns only the explicit public application fields", () => {
		const input = { client_id: "test-client", client_secret: "test-private-secret", customExtension: "private-extension", allauthOrganizationIds: ["organization-one"] };
		const response = publicApplication(input);
		expect(response.organizationIds).toEqual(["organization-one"]);
		expect(JSON.stringify(response)).not.toContain("test-private-secret");
		expect(JSON.stringify(response)).not.toContain("private-extension");
	});
});

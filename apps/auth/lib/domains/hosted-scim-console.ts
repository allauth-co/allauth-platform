import type { OwnedProjectSCIMConsoleRoute } from "../projects/owned-project-scim-console";
import { ownedSCIMManagementPathId } from "../projects/owned-project-scim-management";

/** Bind the already verified accounts request to its own project console route. */
export function hostedScimConsoleRequest(
	request: Request,
	endpoint: string,
	project: string,
	platformOrigin: string,
) {
	const { searchParams } = new URL(request.url);
	const operation = endpoint.slice("scim/".length);
	const rawOrganization = searchParams.get("organizationId");
	const rawConnection = searchParams.get("connectionId");
	const organizationId =
		rawOrganization &&
		ownedSCIMManagementPathId(encodeURIComponent(rawOrganization), 242);
	const connectionId =
		rawConnection &&
		ownedSCIMManagementPathId(encodeURIComponent(rawConnection), 255);
	if (!organizationId || organizationId === "." || organizationId === "..")
		return null;
	let route: OwnedProjectSCIMConsoleRoute;
	if (
		(operation === "list" || operation === "create") &&
		searchParams.size === 1 &&
		request.method === (operation === "list" ? "GET" : "POST")
	) {
		route = { organizationId, operation };
	} else if (
		(operation === "rotate" ||
			operation === "revoke" ||
			operation === "decommission") &&
		request.method === "POST" &&
		searchParams.size === 2 &&
		connectionId &&
		connectionId !== "." &&
		connectionId !== ".."
	) {
		route = { organizationId, operation, connectionId };
	} else return null;

	const url = new URL(platformOrigin);
	url.pathname = `/api/organizations/${encodeURIComponent(organizationId)}/scim`;
	if ("connectionId" in route)
		url.pathname += `/${encodeURIComponent(route.connectionId)}/${route.operation}`;
	url.searchParams.set("project", project);
	const headers = new Headers();
	for (const name of [
		"cookie",
		"user-agent",
		"content-type",
		"sec-fetch-site",
	]) {
		const value = request.headers.get(name);
		if (value) headers.set(name, value);
	}
	if (request.method === "POST") headers.set("origin", platformOrigin);
	return {
		route,
		request: new Request(url, {
			method: request.method,
			headers,
			body: request.body,
			duplex: "half",
		} as RequestInit),
	};
}

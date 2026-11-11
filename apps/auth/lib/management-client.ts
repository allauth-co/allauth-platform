import { authClient, makeAuthClient } from "./auth-client";
import { projectSlug } from "./projects/validation";

const clients = new Map<string, ReturnType<typeof makeAuthClient>>();
/** Platform console calls select a project explicitly; public end-user auth does not use this helper. */
export function getManagementClient(project?: string) {
	if (!project) return authClient;
	projectSlug.parse(project);
	let client = clients.get(project);
	if (!client) {
		const proxyFetch = (input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
			const value = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
			const path = value.replace(`/api/projects/${project}/auth/admin/`, `/api/projects/${project}/auth/project-admin/`);
			return fetch(input instanceof Request ? new Request(path, input) : path, init);
		};
		const fetchImpl = Object.assign(proxyFetch, fetch);
		client = makeAuthClient({ basePath: `/api/projects/${project}/auth`, customFetchImpl: fetchImpl });
		if (clients.size >= 12) clients.delete(clients.keys().next().value!);
		clients.set(project, client);
	}
	return client;
}
export function projectManagementPath(path: string, project?: string): string {
	if (!project) return path;
	projectSlug.parse(project);
	return `${path}${path.includes("?") ? "&" : "?"}project=${encodeURIComponent(project)}`;
}

/** Selects one authentication instance without falling back from an invalid project. */
export function createControlRequest(project?: string) {
	return async function request<T>(
		path: string,
		init: RequestInit = {},
	): Promise<T> {
		if (
			project !== undefined &&
			(!/^[a-z][a-z0-9-]{1,47}$/.test(project) ||
				[
					"admin",
					"platform",
					"auth",
					"api",
					"allauth",
					"public",
					"internal",
				].includes(project))
		)
			throw new Error("Choose a valid project.");
		const authBase =
			project !== undefined
				? `/api/projects/${encodeURIComponent(project)}/auth`
				: "/api/auth";
		const headers = new Headers(init.headers);
		headers.set("Accept", "application/json");
		if (init.body) headers.set("Content-Type", "application/json");
		const response = await fetch(`${authBase}/control/${path}`, {
			...init,
			headers,
			credentials: "same-origin",
			cache: "no-store",
		});
		const payload: unknown = await response.json().catch(() => null);
		if (!response.ok) {
			if (response.status === 401)
				throw new Error("Your session has ended. Sign in again to continue.");
			if (response.status === 403)
				throw new Error("You do not have permission to use this control.");
			if (response.status === 404)
				throw new Error(
					"This control is not available on this deployment yet.",
				);
			const message =
				payload &&
				typeof payload === "object" &&
				"message" in payload &&
				typeof payload.message === "string"
					? payload.message
					: payload &&
							typeof payload === "object" &&
							"error" in payload &&
							typeof payload.error === "string"
						? payload.error
						: `The request could not be completed (HTTP ${response.status}).`;
			throw new Error(message);
		}
		if (payload === null)
			throw new Error(
				"The server returned an unreadable response. Please try again.",
			);
		return payload as T;
	};
}

/** The existing platform instance remains the default when no project is selected. */
export const controlRequest = createControlRequest();

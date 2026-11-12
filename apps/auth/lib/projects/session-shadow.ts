import type { AuthEngine } from "../auth-engine";
import type { AuthEnvironment } from "../configuration";
import { setting } from "../configuration";
import type { ControlPrincipal } from "../control/types";
import type { Project } from "./registry";

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const maximumInFlight = 2;
const deadlineMs = 150;
let inFlight = 0;

type Comparison = "match" | "different" | "unavailable";
interface Observation {
	event: "allauth.project_session_shadow";
	projectId: string;
	outcome: Comparison;
}

/** Preview only in development realms explicitly selected by immutable project ID. */
export function projectSessionShadowSelected(
	env: AuthEnvironment,
	project: Pick<Project, "id" | "environment">,
): boolean {
	if (project.environment !== "development" || !uuid.test(project.id)) return false;
	const configured = setting(env, "ALLAUTH_PROJECT_SESSION_SHADOW_IDS").trim();
	if (!configured) return false;
	const ids = configured.split(",").map((id) => id.trim());
	return ids.length <= 20 && ids.every((id) => uuid.test(id)) && ids.includes(project.id);
}

function identity(value: unknown) {
	if (!value || typeof value !== "object" || !("user" in value) || !("session" in value)) {
		throw new Error("Invalid session result.");
	}
	const { session, user } = value;
	if (!session || typeof session !== "object" || !user || typeof user !== "object" ||
		!("id" in session) || typeof session.id !== "string" ||
		!("userId" in session) || typeof session.userId !== "string" ||
		!("id" in user) || typeof user.id !== "string" ||
		!("email" in user) || typeof user.email !== "string" ||
		!("name" in user) || typeof user.name !== "string" ||
		!("emailVerified" in user) || typeof user.emailVerified !== "boolean") {
		throw new Error("Invalid session identity.");
	}
	return [
		session.id, session.userId, user.id, user.email, user.name, user.emailVerified,
		"impersonatedBy" in session ? session.impersonatedBy ?? null : null,
		"role" in user ? user.role ?? null : null,
		"banned" in user ? user.banned ?? null : null,
	];
}

/**
 * Compare already-authorized reads without taking ownership of the response.
 * A concurrent revocation between the two snapshots can produce a difference.
 */
export function observeProjectSessions(
	engine: AuthEngine,
	options: {
		basePath: string;
		projectId: string;
		read: (headers: Headers) => Promise<ControlPrincipal | null>;
		report?: (event: Observation) => void;
	},
): AuthEngine {
	const report = (outcome: Comparison) => {
		try {
			const event: Observation = {
				event: "allauth.project_session_shadow",
				projectId: options.projectId,
				outcome,
			};
			if (options.report) options.report(event);
			else console.info(JSON.stringify(event));
		} catch {
			// Diagnostics cannot change the authoritative response.
		}
	};
	const compare = async (request: Request, response: Response) => {
		if (request.method !== "GET" || response.status !== 200 ||
			new URL(request.url).pathname !== `${options.basePath}/get-session`) return response;
		if (inFlight >= maximumInFlight) {
			report("unavailable");
			return response;
		}
		inFlight++;
		const completion = (async (): Promise<Comparison> => {
			try {
				const [authoritative, candidate] = await Promise.allSettled([
					response.clone().json() as Promise<unknown>,
					options.read(request.headers),
				]);
				if (authoritative.status === "rejected" || candidate.status === "rejected") return "unavailable";
				const actual = authoritative.value === null ? null : identity(authoritative.value);
				const alternate = candidate.value === null ? null : identity(candidate.value);
				return JSON.stringify(actual) === JSON.stringify(alternate) ? "match" : "different";
			} catch {
				return "unavailable";
			} finally {
				inFlight--;
			}
		})();
		let timer: ReturnType<typeof setTimeout> | undefined;
		const deadline = new Promise<Comparison>((resolve) => {
			timer = setTimeout(resolve, deadlineMs, "unavailable");
		});
		try {
			report(await Promise.race([completion, deadline]));
		} finally {
			clearTimeout(timer);
		}
		return response;
	};
	return {
		...engine,
		async readSession(request) { return compare(request, await engine.readSession(request)); },
		async dispatch(request) { return compare(request, await engine.dispatch(request)); },
	};
}

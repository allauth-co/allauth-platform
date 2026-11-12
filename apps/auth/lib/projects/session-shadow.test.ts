import { describe, expect, it, vi } from "vitest";
import type { AuthEngine } from "../auth-engine";
import { observeProjectSessions, projectSessionShadowSelected } from "./session-shadow";

const projectId = "00000000-0000-4000-8000-000000000017";
const basePath = "/api/projects/development/auth";
const request = new Request(`https://auth.example${basePath}/get-session`);

describe("project session comparison", () => {
	it("selects development realms by an exact immutable ID only", () => {
		const realm = { id: projectId, environment: "development" as const };
		const selected = { ALLAUTH_PROJECT_SESSION_SHADOW_IDS: projectId };
		expect(projectSessionShadowSelected(selected, realm)).toBe(true);
		expect(projectSessionShadowSelected(selected, { ...realm, environment: "production" })).toBe(false);
		expect(projectSessionShadowSelected({ ALLAUTH_PROJECT_SESSION_SHADOW_IDS: "development" }, realm)).toBe(false);
		expect(projectSessionShadowSelected({ ALLAUTH_PROJECT_SESSION_SHADOW_IDS: `${projectId},*` }, realm)).toBe(false);
	});

	it("preserves the authoritative response if the candidate cannot read the session", async () => {
		const sessionCookie = "fixture.session_token=fixture-session; Path=/; HttpOnly";
		const authoritative = Response.json(null, { headers: { "Set-Cookie": sessionCookie } });
		const engine: AuthEngine = {
			dispatch: vi.fn(),
			readPrincipal: vi.fn(),
			readSession: vi.fn().mockResolvedValue(authoritative),
			listAccountSessions: vi.fn(),
			revokeAccountSession: vi.fn(),
			readDirectory: vi.fn(),
		};
		const report = vi.fn();
		const observed = observeProjectSessions(engine, {
			projectId, basePath, report,
			read: async () => { throw new Error("Private database diagnostic"); },
		});
		const response = await observed.readSession(request);
		expect(response).toBe(authoritative);
		expect(response.headers.getSetCookie()).toEqual([sessionCookie]);
		expect(await response.json()).toBeNull();
		expect(report).toHaveBeenCalledExactlyOnceWith({
			event: "allauth.project_session_shadow", projectId, outcome: "unavailable",
		});
	});
});

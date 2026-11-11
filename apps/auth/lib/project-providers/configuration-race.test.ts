import { describe, expect, it } from "vitest";
import type { ControlPrincipal } from "../control/types";
import type { Project } from "../projects/registry";
import { configurationHandler } from "../auth-policy/api";
import type { ConfigurationDependencies } from "../auth-policy/api";
import { defaultAuthPolicy } from "../auth-policy/policy";
import { googleProviderHandler } from "./api";
import type { GoogleProviderDependencies } from "./api";
import { defaultGoogleProvider } from "./google";

const origin = "https://allauth.example";
const project = { id: "fixture-project", name: "Fixture", slug: "fixture-development", workspaceId: "fixture-workspace", schemaName: "allauth_project_0123456789abcdef0123456789abcdef" } as Project;
const actor = { user: { id: "fixture-admin", email: "admin@example.com", emailVerified: true }, session: { id: "fixture-session", userId: "fixture-admin" } } as ControlPrincipal;

describe("authentication method settings concurrency", () => {
	it.each(["policy-first", "provider-first"])("keeps a usable sign-in method when policy and direct-provider writes race: %s", async (order) => {
		let policy = { ...defaultAuthPolicy };
		let google = { ...defaultGoogleProvider(), version: 1, enabled: true, clientId: "fixture.apps.googleusercontent.com", encryptedClientSecret: "fixture-encrypted" };
		let tail = Promise.resolve();
		const serialized = async <T>(work: () => Promise<T>): Promise<T> => {
			const previous = tail; let release = () => {};
			tail = new Promise<void>((resolve) => { release = resolve; });
			await previous;
			try { return await work(); } finally { release(); }
		};
		const policyDependencies: ConfigurationDependencies = {
			origin, authorize: async () => actor,
			resolveScope: async () => ({ type: "project", id: project.id, name: project.name, slug: project.slug, schemaName: project.schemaName }),
			read: async () => ({ version: 0, policy, updatedAt: null }),
			update: async (_id, _version, next) => { await Promise.resolve(); policy = next; return { version: 1, policy, updatedAt: null }; },
			providers: () => ({ google: google.enabled, github: false, microsoft: false, email: true }),
			unenrolledUsers: async () => 0, ownerCanLogin: async () => true,
			serializeWrite: (_scope, _actor, work) => serialized(() => work(policyDependencies)),
		};
		const googleDependencies: GoogleProviderDependencies = {
			origin, brokerGoogleEnabled: false, project: async () => project, authorize: async () => actor,
			read: async () => google,
			update: async (_project, input) => { await Promise.resolve(); google = { ...google, enabled: input.google.enabled, version: 2 }; return google; },
			callbackUrls: async () => [], canDisableGoogle: async () => policy.emailAndPasswordEnabled,
			serializeWrite: (_project, _actor, work) => serialized(() => work(googleDependencies)),
		};
		const request = (url: string, body: unknown) => new Request(`${origin}${url}`, { method: "PATCH", headers: { origin, "content-type": "application/json" }, body: JSON.stringify(body) });
		const changePolicy = () => configurationHandler(policyDependencies)(request(`/api/admin/configuration?project=${project.slug}`, { version: 0, policy: { ...policy, emailAndPasswordEnabled: false } }));
		const changeGoogle = () => googleProviderHandler(googleDependencies)(request(`/api/admin/projects/${project.slug}/providers/google`, { version: 1, google: { enabled: false, clientId: "" } }), project.slug);
		const results = await Promise.allSettled(order === "policy-first" ? [changePolicy(), changeGoogle()] : [changeGoogle(), changePolicy()]);
		expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
		const rejected = results.find((result) => result.status === "rejected");
		expect(rejected?.status === "rejected" ? rejected.reason : null).toMatchObject({ statusCode: 400 });
		expect(policy.emailAndPasswordEnabled || google.enabled).toBe(true);
	});
});

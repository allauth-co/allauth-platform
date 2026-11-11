import { describe, expect, it } from "vitest";
import { nativePasskeyCapability, selectedNativePasskeys } from "./project-native-passkeys";

const project = { id: "7046c686-3816-42ae-82e3-ad71b96d3282", slug: "nativeapp-production", environment: "production" as const, primaryOrigin: "https://nativeapp.example" };
const fingerprint = Array.from({ length: 32 }, (_, index) => index.toString(16).padStart(2, "0")).join(":").toUpperCase();
const policy = () => ({ enabled: true, projectId: project.id, environment: "production", rpOrigin: project.primaryOrigin, ios: { teamId: "TESTTEAM01", bundleId: "com.nativeapp.mobile" }, android: [{ packageName: "com.nativeapp.mobile", certificateSha256: fingerprint }] });
const env = (value: unknown) => ({ ALLAUTH_PROJECT_NATIVE_PASSKEYS: JSON.stringify({ [project.slug]: value }) });

describe("exact project native passkey policy", () => {
	it("derives Android origin from reviewed raw certificate digest bytes and returns only public capability", () => {
		const selected = selectedNativePasskeys(env(policy()), project);
		expect(selected).toMatchObject({ enabled: true, ios: true, android: true, rpId: "nativeapp.example", expectedOrigins: ["https://nativeapp.example", `android:apk-key-hash:${Buffer.from(Array.from({ length: 32 }, (_, index) => index)).toString("base64url")}`] });
		expect(nativePasskeyCapability(selected)).toEqual({ enabled: true, ios: true, android: true, rpId: "nativeapp.example" });
		expect(JSON.stringify(nativePasskeyCapability(selected))).not.toMatch(/certificate|teamId|version|bundleId/);
	});
	it.each([undefined, "", "invalid JSON", "[]", "null"]) ("stays disabled for absent/malformed policy %s", (value) => expect(selectedNativePasskeys({ ALLAUTH_PROJECT_NATIVE_PASSKEYS: value }, project).enabled).toBe(false));
	it.each([
		{ projectId: "e84024b0-577c-4d98-89b4-888f6bb34e8c" }, { environment: "development" }, { enabled: false }, { rpOrigin: "https://another.example" }, { rpOrigin: "https://nativeapp.example/path" }, { rpOrigin: "https://*.nativeapp.example" }, { rpOrigin: "http://localhost:5100" }, { rpOrigin: "https://127.0.0.1" }, { origins: ["android:apk-key-hash:attacker"] }, { android: [{ packageName: "com.nativeapp.mobile", certificateSha256: "unverified" }] }, { ios: undefined, android: [] },
	])("fails closed for mismatched, undeclared or unverified identity fields %j", (change) => expect(selectedNativePasskeys(env({ ...policy(), ...change }), project).enabled).toBe(false));
	it("never enables native RP on a loopback realm or a different hosted origin", () => {
		expect(selectedNativePasskeys(env(policy()), { ...project, primaryOrigin: "http://localhost:5100" }).enabled).toBe(false);
		expect(selectedNativePasskeys(env(policy()), project, "https://auth.nativeapp.example").enabled).toBe(false);
	});
	it("does not borrow production policy for a development slug or reused immutable project ID", () => {
		expect(selectedNativePasskeys(env(policy()), { ...project, slug: "nativeapp-development", environment: "development" }).enabled).toBe(false);
		expect(selectedNativePasskeys(env(policy()), { ...project, id: "a4dadc35-1177-4d07-805d-1a110d8720be" }).enabled).toBe(false);
	});
	it("hashes only the selected policy so unrelated tenant updates do not affect its cache key", () => {
		const initial = selectedNativePasskeys(env(policy()), project);
		const unrelated = selectedNativePasskeys({ ALLAUTH_PROJECT_NATIVE_PASSKEYS: JSON.stringify({ [project.slug]: policy(), another: { invalid: true } }) }, project);
		const rotated = selectedNativePasskeys(env({ ...policy(), android: [{ packageName: "com.nativeapp.mobile", certificateSha256: Array(32).fill("FF").join(":") }] }), project);
		expect(unrelated.version).toBe(initial.version); expect(rotated.version).not.toBe(initial.version);
	});
});

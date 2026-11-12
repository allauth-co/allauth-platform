// @vitest-environment happy-dom
// @vitest-environment-options {"url":"https://accounts.device-fixture.example"}

import type { ComponentProps } from "react";
import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { DeviceApproval } from "@/components/features/device";

vi.mock("next/link", () => ({
	default: ({ children, ...props }: ComponentProps<"a">) =>
		createElement("a", props, children),
}));

const origin = "https://accounts.device-fixture.example";
const project = "fixture-project";
const initialCode = "ABCD EFGH";
const hosted = {
	project,
	initialCode,
	basePath: "/api/auth",
	reauthentication: { signInURL: "/sign-in", returnPath: "/account/device" },
} satisfies ComponentProps<typeof DeviceApproval>;
const user = {
	id: "project-user",
	email: "project-user@fixture.example",
	emailVerified: true,
};
let dispose: (() => Promise<void>) | undefined;

beforeEach(() => vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true));
afterEach(async () => {
	await dispose?.();
	dispose = undefined;
	vi.unstubAllGlobals();
});

async function render(
	props: ComponentProps<typeof DeviceApproval>,
	handle: (url: URL) => Response | Promise<Response>,
) {
	const requests: { url: string; method: string; body?: unknown }[] = [];
	vi.stubGlobal("fetch", async (input: string, init?: RequestInit) => {
		const request = new Request(new URL(input, origin), init);
		const url = new URL(request.url);
		expect(url.origin).toBe(origin);
		expect(request.credentials).toBe("same-origin");
		expect(request.headers.has("authorization")).toBe(false);
		requests.push({
			url: request.url,
			method: request.method,
			body: request.body ? await request.json() : undefined,
		});
		return handle(url);
	});
	const container = document.createElement("div");
	document.body.appendChild(container);
	const root = createRoot(container);
	dispose = async () => {
		await act(async () => root.unmount());
		container.remove();
	};
	await act(async () => root.render(createElement(DeviceApproval, props)));
	return { container, requests };
}

it("returns to the same hosted review with the original code after sign-in", async () => {
	const { container, requests } = await render(hosted, () =>
		Response.json(null),
	);
	const link = container.querySelector("a");
	if (!link) throw new Error("Expected a project sign-in link.");
	const signIn = new URL(link.href);
	expect(signIn.origin + signIn.pathname).toBe(`${origin}/sign-in`);
	expect([...signIn.searchParams.keys()]).toEqual(["callbackUrl"]);
	const review = new URL(signIn.searchParams.get("callbackUrl")!, origin);
	expect(review.origin + review.pathname).toBe(`${origin}/account/device`);
	expect([...review.searchParams.entries()]).toEqual([
		["user_code", initialCode],
	]);
	expect(requests.map(({ url }) => new URL(url).pathname)).toEqual([
		"/api/auth/get-session",
	]);
});

it.each([
	"approve",
	"deny",
] as const)("requires explicit review before %s on the hosted realm", async (decision) => {
	const { container, requests } = await render(hosted, ({ pathname: path }) => {
		if (path.endsWith("/get-session"))
			return Response.json({
				user,
				session: { id: "project-session", userId: user.id },
			});
		if (path === "/api/auth/device")
			return Response.json({
				user_code: "ABCDEFGH",
				client_id: "registered-device-client",
				status: "pending",
				scope: "openid profile",
			});
		return Response.json({ success: true });
	});
	expect(container.textContent).toContain(user.email);
	expect(requests.map(({ url }) => new URL(url).pathname)).toEqual([
		"/api/auth/get-session",
	]);
	const form = container.querySelector("form");
	if (!form) throw new Error("Expected the explicit review form.");
	await act(async () =>
		form.dispatchEvent(
			new Event("submit", { bubbles: true, cancelable: true }),
		),
	);
	expect(container.textContent).toContain("registered-device-client");
	expect(requests).toHaveLength(2);
	const review = new URL(requests[1]!.url);
	expect(review.pathname).toBe("/api/auth/device");
	expect(review.searchParams.get("user_code")).toBe(initialCode);
	expect(requests[1]!.method).toBe("GET");
	const button = [...container.querySelectorAll("button")].find(
		({ textContent }) =>
			textContent === (decision === "approve" ? "Approve device" : "Deny"),
	);
	if (!button) throw new Error("Expected a separate device decision.");
	await act(async () => button.click());
	expect(requests).toHaveLength(3);
	const completed = requests[2]!;
	expect(new URL(completed.url).pathname).toBe(`/api/auth/device/${decision}`);
	expect(completed.method).toBe("POST");
	expect(completed.body).toEqual({ userCode: "ABCDEFGH" });
	expect(container.textContent).toContain(
		decision === "approve" ? "Device access approved" : "Device access denied",
	);
});

it("keeps direct-only review scoped to the project and uses the app's sign-in", async () => {
	const { container, requests } = await render({ project, initialCode }, () =>
		Response.json(null),
	);
	expect(container.querySelector("a")).toBeNull();
	expect(container.textContent).toContain(
		"Sign in through this project's application",
	);
	expect(requests.map(({ url }) => new URL(url).pathname)).toEqual([
		`/api/projects/${project}/auth/get-session`,
	]);
});

it("requires another explicit review after the browser signs in again", async () => {
	let sessionId = "old-session";
	const { container, requests } = await render(hosted, ({ pathname }) => {
		if (pathname.endsWith("/get-session"))
			return Response.json({
				user,
				session: { id: sessionId, userId: user.id },
			});
		return Response.json({
			user_code: initialCode,
			status: "pending",
			client_id: "device-client",
		});
	});
	const form = container.querySelector("form");
	if (!form) throw new Error("Expected the explicit review form.");
	await act(async () =>
		form.dispatchEvent(
			new Event("submit", { bubbles: true, cancelable: true }),
		),
	);
	expect(container.textContent).toContain("device-client");
	sessionId = "new-session";
	await act(async () =>
		window.dispatchEvent(
			new StorageEvent("storage", { key: "allauth:session:/api/auth" }),
		),
	);
	expect(container.textContent).not.toContain("device-client");
	expect(requests.map(({ url }) => new URL(url).pathname)).toEqual([
		"/api/auth/get-session",
		"/api/auth/device",
		"/api/auth/get-session",
	]);
});

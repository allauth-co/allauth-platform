import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { deviceRequestError } from "./device";

/** @see ./server.ts featureBoundaries requires a fresh, verified session for device review and consent. */
describe("device request errors", () => {
	it.each([401, 403])("explains authentication recovery for HTTP %i instead of blaming a valid code", (status) => {
		const message = deviceRequestError({ status, error_description: "The code is invalid or has expired." });
		expect(message).toContain("Sign in again");
		expect(message).toContain("verified account");
		expect(message).not.toContain("invalid");
		expect(message).not.toContain("expired");
	});

	it.each(["The user code has expired.", "Invalid user code."])("preserves the server's authoritative code failure: %s", (error_description) => {
		expect(deviceRequestError({ status: 400, error_description })).toBe(error_description);
	});

	it("uses the server message when no protocol description is supplied", () => {
		expect(deviceRequestError({ status: 400, message: "This request belongs to another account." })).toBe("This request belongs to another account.");
		expect(deviceRequestError({ status: 400, error_description: "  ", message: "The request has already been denied." })).toBe("The request has already been denied.");
	});

	it.each([
		{},
		{ error_description: { message: "not a string" }, message: ["not a string"] },
		{ error_description: false, message: 42 },
		{ error_description: " ", message: "\n" },
	])("provides a safe fallback for malformed error fields %j", (error) => {
		const message = deviceRequestError(error);
		expect(message).toBe("The device request could not be completed. Please try again.");
	});

	it("keeps server-provided text escaped when rendered as a React error", () => {
		const message = deviceRequestError({ status: 400, error_description: '<img src=x onerror="alert(1)">' });
		const html = renderToStaticMarkup(createElement("p", { role: "alert" }, message));
		expect(html).toContain("&lt;img");
		expect(html).not.toContain("<img");
	});
});

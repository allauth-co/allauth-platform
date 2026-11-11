import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

function layer(styles: string, selector: string) {
	const rule = styles.slice(styles.indexOf(`${selector} {`)).split("}")[0];
	return Number(rule?.match(/z-index:\s*(\d+)/)?.[1] ?? 0);
}

/** @see https://www.radix-ui.com/primitives/docs/components/select#portal */
describe("Console dropdown portal layering", () => {
	it("keeps user and role options above the organization and user detail panels", () => {
		const globals = readFileSync(new URL("../../app/globals.css", import.meta.url), "utf8");
		const consoleStyles = readFileSync(new URL("../../components/console/console.css", import.meta.url), "utf8");
		expect(layer(globals, ".allauth-select-content")).toBeGreaterThan(
			layer(consoleStyles, ".console-panel-backdrop"),
		);
	});
});

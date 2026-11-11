import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { ApplicationSettingsConsole } from "@/components/console/application-settings";
import type { ApplicationSettings } from "@/lib/branding/types";

const settings: ApplicationSettings = {
	applicationId: "application-a",
	workspaceId: "workspace-a",
	version: 3,
	branding: {
		name: "Selected application",
		supportEmail: "help@selected.example",
		logoUrl: "https://assets.allauth.co/branding/workspace-a/application-a/light.png",
		logoDarkUrl: "https://assets.allauth.co/branding/workspace-a/application-a/dark.png",
		faviconUrl: "https://assets.allauth.co/branding/workspace-a/application-a/icon.png",
		primaryColor: "#315bff",
		darkPrimaryColor: "#7892ff",
		showPoweredBy: true,
	},
	createdAt: "2026-10-07T00:00:00.000Z",
	updatedAt: "2026-10-07T00:00:00.000Z",
	storage: { available: true, maxFileSize: 2_097_152, formats: ["image/png", "image/jpeg", "image/webp", "image/x-icon"] },
};

function render(project?: string, value = settings) {
	const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
	client.setQueryData(["console-application-settings", "selected"], value);
	client.setQueryData(["console-application-settings", "other"], {
		...settings,
		branding: { ...settings.branding, name: "Other application's private draft" },
	});
	const html = renderToStaticMarkup(createElement(QueryClientProvider, { client }, createElement(ApplicationSettingsConsole, { project, workspace: "workspace-a" })));
	client.clear();
	return html;
}

describe("application settings rendered controls", () => {
	it("marks only Save buttons as submit and every asset/switch action as a non-submit control", () => {
		const html = render("selected");
		const buttons = html.match(/<button\b[^>]*>[\s\S]*?<\/button>/g) ?? [];
		expect(buttons.filter((button) => button.includes('type="submit"'))).toHaveLength(2);
		for (const button of buttons) {
			if (button.includes("Save changes")) expect(button).toContain('type="submit"');
			else expect(button).toContain('type="button"');
		}
		expect(html).toContain("Uploads save immediately");
		expect(html).toContain("Removing an image takes effect when you save changes");
	});

	it("renders only the selected project's branding with distinct real light/dark assets", () => {
		const html = render("selected");
		expect(html).toContain("Selected application");
		expect(html).toContain(settings.branding.logoUrl!);
		expect(html).toContain(settings.branding.logoDarkUrl!);
		expect(html).not.toContain("Other application");
		expect(html).toContain("Shared across this application’s environments");
	});

	it("represents unavailable storage honestly and disables image selection/uploads", () => {
		const html = render("selected", { ...settings, storage: { ...settings.storage, available: false } });
		expect(html).toContain("Cloudflare storage is not configured");
		for (const input of html.match(/<input\b[^>]*type="file"[^>]*>/g) ?? []) expect(input).toContain("disabled");
		for (const button of html.match(/<button\b[^>]*>[\s\S]*?<\/button>/g) ?? []) {
			if (button.includes("Replace")) expect(button).toContain("disabled");
		}
	});

	it("asks for an actual application selection without using the platform's settings as a fallback", () => {
		const html = render();
		expect(html).toContain("Choose an application");
		expect(html).toContain("/admin/projects?workspace=workspace-a");
		expect(html).not.toContain("Selected application");
		expect(html).not.toContain('<input type="file"');
	});
});

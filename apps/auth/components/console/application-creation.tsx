"use client";

import { useQueryClient } from "@tanstack/react-query";
import { Box } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { AppSelect, AppSelectOption } from "@/components/ui/app-select";
import { Button } from "@/components/ui/button";
import {
	applicationCreationInput,
	missingApplicationEnvironment,
} from "@/lib/console/application-creation";
import type { ApplicationCreationDraft } from "@/lib/console/application-creation";
import { DetailPanel, managementRequest } from "./common";
import type { CreatedApplication } from "./application-connection";
import type { ConsoleProject } from "./shell";
import type { ConsoleWorkspace } from "./workspace-client";

export interface ApplicationCreationTarget {
	workspace: ConsoleWorkspace;
	instances?: readonly ConsoleProject[];
}

/** Shared creation dialog keeps the workspace and existing application fixed. */
export function ApplicationCreationPanel({
	target,
	onClose,
	onCreated,
}: {
	target: ApplicationCreationTarget;
	onClose: () => void;
	onCreated: (result: CreatedApplication) => void;
}) {
	const cache = useQueryClient();
	const application = target.instances?.[0];
	const missing = target.instances
		? missingApplicationEnvironment(target.instances)
		: null;
	const [draft, setDraft] = useState<ApplicationCreationDraft>({
		name: application?.name ?? "",
		slug: "",
		primaryOrigin: "",
		origins: "",
		environment: missing ?? "development",
	});
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState("");
	const create = async () => {
		if (busy) return;
		setBusy(true);
		setError("");
		try {
			const payload = applicationCreationInput(
				draft,
				target.workspace.id,
				target.instances,
			);
			const result = await managementRequest<CreatedApplication>(
				"/api/admin/projects",
				{
					method: "POST",
					body: JSON.stringify(payload),
				},
			);
			await Promise.all([
				cache.invalidateQueries({ queryKey: ["platform-projects"] }),
				cache.invalidateQueries({ queryKey: ["console-workspaces"] }),
			]);
			onCreated(result);
		} catch (cause) {
			const message =
				cause instanceof Error ? cause.message : "The request failed.";
			setError(message);
			toast.error(message);
		} finally {
			setBusy(false);
		}
	};
	return (
		<DetailPanel
			title={application ? "Add application environment" : "Create application"}
			onClose={() => {
				if (!busy) onClose();
			}}
		>
			<p className="console-panel-intro">
				{application
					? "Development and production have separate users, sessions, and integration keys. Workspace access stays shared."
					: "Start with a development environment for your app. Authentication, organizations, and access controls can be configured after creation."}
			</p>
			<form
				className="console-form"
				onSubmit={(event) => {
					event.preventDefault();
					void create();
				}}
			>
				<div>
					<label htmlFor="project-workspace">Workspace</label>
					<input
						id="project-workspace"
						value={target.workspace.name}
						readOnly
					/>
				</div>
				<div>
					<label htmlFor="project-name">Application name</label>
					<input
						id="project-name"
						required
						minLength={2}
						maxLength={100}
						placeholder="Acme web"
						value={draft.name}
						readOnly={Boolean(application)}
						disabled={busy}
						onChange={(event) =>
							setDraft({ ...draft, name: event.target.value })
						}
					/>
				</div>
				<div>
					<label htmlFor="project-environment">Environment</label>
					<AppSelect
						id="project-environment"
						value={draft.environment}
						disabled={busy || Boolean(application)}
						onValueChange={(value) => {
							if (value === "development" || value === "production")
								setDraft({ ...draft, environment: value });
						}}
					>
						<AppSelectOption value="development">Development</AppSelectOption>
						<AppSelectOption value="production">Production</AppSelectOption>
					</AppSelect>
					<p>
						Production requires an HTTPS app origin. Use a loopback origin for
						local development.
					</p>
				</div>
				<div>
					<label htmlFor="project-slug">Environment identifier</label>
					<input
						id="project-slug"
						required
						minLength={2}
						maxLength={48}
						pattern="[a-z][a-z0-9-]{1,47}"
						autoCapitalize="none"
						placeholder={
							draft.environment === "development"
								? "acme-development"
								: "acme-production"
						}
						value={draft.slug}
						disabled={busy}
						onChange={(event) =>
							setDraft({ ...draft, slug: event.target.value })
						}
					/>
					<p>A unique identifier used in your server configuration.</p>
				</div>
				<div>
					<label htmlFor="project-origin">Primary app origin</label>
					<input
						id="project-origin"
						required
						type="url"
						placeholder={
							draft.environment === "development"
								? "http://localhost:3000"
								: "https://app.example.com"
						}
						value={draft.primaryOrigin}
						disabled={busy}
						onChange={(event) =>
							setDraft({ ...draft, primaryOrigin: event.target.value })
						}
					/>
				</div>
				<div>
					<label htmlFor="project-origins">Additional exact origins</label>
					<textarea
						id="project-origins"
						placeholder="https://www.example.com"
						value={draft.origins}
						disabled={busy}
						onChange={(event) =>
							setDraft({ ...draft, origins: event.target.value })
						}
					/>
					<p>
						Separate up to 10 origins with spaces or new lines. Register only
						origins your application controls.
					</p>
				</div>
				<div className="application-create-summary">
					<Box size={16} aria-hidden="true" />
					<span>
						<strong>{draft.name || "Your application"}</strong>
						<small>
							{target.workspace.name} ·{" "}
							{draft.environment === "production"
								? "Production"
								: "Development"}
						</small>
					</span>
				</div>
				{error && (
					<p role="alert" className="console-inline-error">
						{error}
					</p>
				)}
				<Button
					type="submit"
					className="console-primary"
					disabled={busy || (Boolean(application) && !missing)}
				>
					{busy
						? "Creating…"
						: application
							? "Create environment"
							: "Create application"}
				</Button>
			</form>
		</DetailPanel>
	);
}

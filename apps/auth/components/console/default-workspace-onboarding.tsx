"use client";

import { LayoutGrid } from "lucide-react";
import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { managementRequest } from "./common";

type SetupResult = {
	workspace?: { id: string; name?: string };
	created: boolean;
	reason?: string;
};

/** Prepare the first platform workspace after the verified user enters Console. */
export function DefaultWorkspaceOnboarding({ onReady, onSkip }: {
	onReady: (workspaceId: string) => void | Promise<void>;
	onSkip: () => void;
}) {
	const [attempt, setAttempt] = useState(0);
	const [error, setError] = useState("");
	useEffect(() => {
		let active = true;
		setError("");
		void (async () => {
			try {
				const result = await managementRequest<SetupResult>("/api/workspaces/onboarding", { method: "POST", body: "{}" });
				if (!active) return;
				if (result.workspace?.id) await onReady(result.workspace.id);
				else onSkip();
			} catch (cause) {
				if (active) setError(cause instanceof Error ? cause.message : "Please try again.");
			}
		})();
		return () => { active = false; };
	}, [attempt, onReady, onSkip]);

	return (
		<section className="console-onboarding-empty" aria-label="Workspace setup">
			<span className="console-empty-icon"><LayoutGrid size={24} /></span>
			<h2>{error ? "Your workspace couldn't be set up" : "Your workspace is on its way"}</h2>
			{error ? (
				<>
					<p role="alert">{error}</p>
					<div className="flex flex-wrap justify-center gap-3">
						<Button className="console-primary" onClick={() => setAttempt((value) => value + 1)}>Try again</Button>
						<Button variant="outline" onClick={onSkip}>Create a workspace myself</Button>
					</div>
				</>
			) : <p role="status" aria-live="polite">Creating your workspace. You can rename it and invite your team whenever you're ready.</p>}
		</section>
	);
}

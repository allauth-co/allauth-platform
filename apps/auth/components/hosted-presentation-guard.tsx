"use client";

import { usePathname, useSearchParams } from "next/navigation";
import type { ReactNode } from "react";
import { useEffect, useState } from "react";
import type { HostedPresentation } from "@/lib/domains/hosted-presentation";
import { hostedPresentationPath } from "@/lib/domains/hosted-presentation";
import { HostedProjectUnavailable } from "./hosted-project-unavailable";

type Navigation = {
	location: string;
	status: "ready" | "pending" | "unavailable";
};

/** A shared Next layout can survive navigation after a project writer changes. */
export function HostedPresentationGuard({
	mode,
	children,
}: {
	mode: HostedPresentation;
	children: ReactNode;
}) {
	const location = `${usePathname()}?${useSearchParams()}`;
	const [navigation, setNavigation] = useState<Navigation>({
		location,
		status: "ready",
	});
	if (navigation.location !== location) {
		setNavigation({ location, status: "pending" });
	}

	useEffect(() => {
		if (navigation.status !== "pending") return;
		const controller = new AbortController();
		let currentNavigation = true;
		const timeout = setTimeout(() => controller.abort(), 5000);
		async function checkMode() {
			try {
				const response = await fetch(hostedPresentationPath, {
					cache: "no-store",
					signal: controller.signal,
				});
				if (!response.ok)
					throw new Error("Hosted presentation is unavailable.");
				const payload: unknown = await response.json();
				if (!currentNavigation) return;
				const current =
					payload && typeof payload === "object" && "mode" in payload
						? payload.mode
						: undefined;
				if (
					current !== "legacy" &&
					current !== "preview" &&
					current !== "allauth"
				)
					throw new Error("Invalid hosted presentation.");
				if (current !== mode) {
					window.location.reload();
					return;
				}
				setNavigation({ location: navigation.location, status: "ready" });
			} catch {
				if (currentNavigation)
					setNavigation({
						location: navigation.location,
						status: "unavailable",
					});
			} finally {
				clearTimeout(timeout);
			}
		}
		void checkMode();
		return () => {
			currentNavigation = false;
			clearTimeout(timeout);
			controller.abort();
		};
	}, [mode, navigation]);

	if (navigation.location !== location || navigation.status === "pending") {
		return (
			<p role="status" className="p-5 text-muted-foreground">
				Loading AllAuth…
			</p>
		);
	}
	if (navigation.status === "unavailable") {
		return (
			<div className="text-center">
				<HostedProjectUnavailable />
				<button
					className="underline"
					onClick={() => window.location.reload()}
					type="button"
				>
					Retry
				</button>
			</div>
		);
	}
	return children;
}

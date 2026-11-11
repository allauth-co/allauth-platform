"use client";

import { useEffect, useRef, useState } from "react";
import { authError, proxyBasePath } from "./helpers";

type DisplaySession = {
	session: { id: string; expiresAt: string };
	user: { email: string };
	actor: { email: string };
};
type Status = {
	support: DisplaySession | null;
	canRestore: boolean;
	expired: boolean;
};
const object = (value: unknown): value is Record<string, unknown> =>
	!!value && typeof value === "object" && !Array.isArray(value);
function displayStatus(value: unknown): Status {
	if (
		!object(value) ||
		typeof value.canRestore !== "boolean" ||
		typeof value.expired !== "boolean"
	)
		throw new Error("Support session status could not be checked.");
	if (value.support === null)
		return {
			support: null,
			canRestore: value.canRestore,
			expired: value.expired,
		};
	const current = value.support;
	if (
		!object(current) ||
		!object(current.session) ||
		typeof current.session.id !== "string" ||
		typeof current.session.expiresAt !== "string" ||
		!Number.isFinite(Date.parse(current.session.expiresAt)) ||
		!object(current.user) ||
		typeof current.user.email !== "string" ||
		!object(current.actor) ||
		typeof current.actor.email !== "string"
	)
		throw new Error("Support session status could not be checked.");
	return {
		support: {
			session: { id: current.session.id, expiresAt: current.session.expiresAt },
			user: { email: current.user.email },
			actor: { email: current.actor.email },
		},
		canRestore: value.canRestore,
		expired: value.expired,
	};
}

/** Persistent target/actor identification and an explicit end action for opt-in support access. */
export function SupportBanner({ basePath }: { basePath: string }) {
	const path = proxyBasePath(basePath);
	const [status, setStatus] = useState<Status | null>(null);
	const [error, setError] = useState("");
	const [busy, setBusy] = useState(false);
	const [refresh, setRefresh] = useState(0);
	const [now, setNow] = useState(Date.now());
	const stopController = useRef<AbortController | null>(null);
	useEffect(() => {
		setStatus(null);
		setError("");
		setBusy(false);
		const controller = new AbortController();
		let pending = false;
		const load = async () => {
			if (pending) return;
			pending = true;
			try {
				const response = await fetch(`${path}/support/session`, {
					credentials: "same-origin",
					cache: "no-store",
					signal: controller.signal,
				});
				if (!response.ok)
					throw new Error("Support session status could not be checked.");
				const next = displayStatus(await response.json());
				if (!controller.signal.aborted) {
					setStatus(next);
					setError("");
					setNow(Date.now());
				}
			} catch (cause) {
				if (!controller.signal.aborted) setError(authError(cause));
			} finally {
				pending = false;
			}
		};
		void load();
		const timer = window.setInterval(() => void load(), 30_000);
		const tick = window.setInterval(() => setNow(Date.now()), 1000);
		const focus = () => void load();
		window.addEventListener("focus", focus);
		return () => {
			controller.abort();
			stopController.current?.abort();
			window.clearInterval(timer);
			window.clearInterval(tick);
			window.removeEventListener("focus", focus);
		};
	}, [path, refresh]);
	const stop = async () => {
		setBusy(true);
		setError("");
		const controller = new AbortController();
		stopController.current = controller;
		try {
			const response = await fetch(`${path}/support/stop`, {
				method: "POST",
				credentials: "same-origin",
				cache: "no-store",
				headers: { "content-type": "application/json" },
				body: "{}",
				signal: controller.signal,
			});
			const data: unknown = await response.json();
			if (!response.ok) throw new Error(authError(data));
			if (
				!object(data) ||
				data.success !== true ||
				typeof data.consoleReturnURL !== "string"
			)
				throw new Error("The support session could not be ended.");
			const destination = new URL(
				typeof data.applicationReturnURL === "string"
					? data.applicationReturnURL
					: data.consoleReturnURL,
			);
			if (
				!["http:", "https:"].includes(destination.protocol) ||
				destination.username ||
				destination.password
			)
				throw new Error("The console address could not be verified.");
			if (!controller.signal.aborted) window.location.assign(destination.href);
		} catch (cause) {
			if (!controller.signal.aborted) setError(authError(cause));
		} finally {
			if (!controller.signal.aborted) setBusy(false);
		}
	};
	const current = status?.support;
	const expired =
		status?.expired ||
		(current && Date.parse(current.session.expiresAt) <= now);
	if (!current && !status?.canRestore && !error) return null;
	return (
		<aside
			className="allauth allauth-support-banner"
			aria-label="Support session"
		>
			<div>
				{current && !expired ? (
					<>
						<strong>Support session · {current.user.email}</strong>
						<p>
							Started by {current.actor.email}. Expires{" "}
							<time dateTime={current.session.expiresAt}>
								{new Date(current.session.expiresAt).toLocaleTimeString([], {
									hour: "numeric",
									minute: "2-digit",
								})}
							</time>
							.
						</p>
					</>
				) : status?.canRestore ? (
					<>
						<strong>Support session ended</strong>
						<p>Restore your previous sign-in or return to AllAuth.</p>
					</>
				) : (
					<strong>Support session status</strong>
				)}
				{error && <p role="alert">{error}</p>}
			</div>
			{current || status?.canRestore ? (
				<button
					type="button"
					className="allauth-button allauth-button-secondary"
					disabled={busy}
					onClick={() => void stop()}
				>
					{busy
						? "Ending…"
						: expired
							? "Restore previous sign-in"
							: "End support session"}
				</button>
			) : (
				<button
					type="button"
					className="allauth-button allauth-button-secondary"
					onClick={() => setRefresh((value) => value + 1)}
				>
					Retry
				</button>
			)}
		</aside>
	);
}

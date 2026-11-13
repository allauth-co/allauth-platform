"use client";

import { useRef, useState } from "react";
import { toast } from "sonner";
import { oauthBrowserQuery, submitOAuthBrowserAction } from "./oauth-browser";
import { errorMessage } from "./shared";

type Selection =
	| { kind: "account"; id: string; sessionToken: string }
	| { kind: "organization"; id: string };

function property(value: unknown, key: string): unknown {
	return value !== null && typeof value === "object" && key in value
		? Reflect.get(value, key)
		: undefined;
}

async function activateSelection(selection: Selection, query: string) {
	const signed = oauthBrowserQuery(query);
	if (!signed)
		throw new Error("This authorization request is invalid or has expired");
	const isAccount = selection.kind === "account";
	const response = await fetch(
		isAccount
			? "/api/auth/multi-session/set-active"
			: "/api/auth/organization/set-active",
		{
			method: "POST",
			credentials: "same-origin",
			cache: "no-store",
			redirect: "error",
			headers: {
				accept: "application/json",
				"content-type": "application/json",
			},
			body: JSON.stringify(
				isAccount
					? { sessionToken: selection.sessionToken }
					: { organizationId: selection.id },
			),
		},
	);
	const body: unknown = await response.json().catch(() => null);
	const active = isAccount ? property(body, "session") : body;
	if (!response.ok || property(active, "id") !== selection.id) {
		const message = property(body, "message");
		throw new Error(
			typeof message === "string"
				? message
				: isAccount
					? "Failed to set active session"
					: "Failed to set active organization",
		);
	}
	await submitOAuthBrowserAction(
		"continue",
		signed,
		isAccount ? { selected: true } : { postLogin: true },
	);
}

/** Hold all picker choices while the browser selects an account and resumes authorization. */
export function useOAuthPicker(query: string) {
	const locked = useRef(false);
	const [pending, setPending] = useState(false);
	async function choose(selection: Selection) {
		if (locked.current) return;
		locked.current = true;
		setPending(true);
		try {
			await activateSelection(selection, query);
		} catch (error) {
			locked.current = false;
			setPending(false);
			toast.error(errorMessage(error));
		}
	}
	return { choose, pending };
}

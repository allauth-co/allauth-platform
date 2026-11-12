"use client";

import { browserSupportsWebAuthnAutofill } from "@simplewebauthn/browser";
import { useCallback, useEffect, useRef, useState } from "react";
import { appPath, authError } from "@/sdk/helpers";
import { useAllAuth } from "@/sdk/react";

type PasskeyAttempt = {
	controller: AbortController;
	identifier?: HTMLInputElement;
};

/** Start conditional WebAuthn only while this hosted identifier is present. */
export function useHostedPasskeySignIn({
	destination,
	enabled,
}: {
	destination: string;
	enabled: boolean;
}) {
	const { capabilities, challenge, client } = useAllAuth();
	const available = enabled && capabilities !== null && !challenge;
	const active = useRef<PasskeyAttempt | null>(null);
	const [identifier, identifierRef] = useState<HTMLInputElement | null>(null);
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState("");

	const cancelAutofill = useCallback(() => {
		const attempt = active.current;
		if (!attempt?.identifier) return;
		active.current = null;
		attempt.controller.abort();
	}, []);

	const authenticate = useCallback(
		async (attempt: PasskeyAttempt) => {
			const signal = attempt.controller.signal;
			const input = attempt.identifier;
			try {
				if (
					input &&
					(!input.isConnected ||
						!input.autocomplete.endsWith(" webauthn") ||
						!(await browserSupportsWebAuthnAutofill()) ||
						signal.aborted ||
						!input.isConnected)
				)
					return;
				const result = await client.signIn.passkey({
					autoFill: Boolean(input),
					fetchOptions: { signal },
				});
				if (signal.aborted) return;
				if (result.error) throw result.error;
				const target = appPath(destination);
				if (result.data?.twoFactorRedirect === true) {
					window.location.assign(
						`/two-factor?${new URLSearchParams({ callbackUrl: target })}`,
					);
				} else if (result.data?.user?.id) {
					window.location.assign(target);
				} else {
					throw new Error(
						"Passkey sign-in could not be confirmed. Please try again.",
					);
				}
			} catch (cause) {
				if (!input && !signal.aborted) setError(authError(cause));
			} finally {
				if (active.current === attempt && !signal.aborted) {
					active.current = null;
					if (!input) setBusy(false);
				}
			}
		},
		[client, destination],
	);

	useEffect(() => {
		setBusy(false);
		setError("");
		return () => {
			const current = active.current;
			active.current = null;
			current?.controller.abort();
		};
	}, [authenticate, available]);

	useEffect(() => {
		if (!available || !identifier || active.current) return;
		const attempt = { controller: new AbortController(), identifier };
		active.current = attempt;
		void authenticate(attempt);
		return () => {
			if (active.current === attempt) active.current = null;
			attempt.controller.abort();
		};
	}, [available, authenticate, identifier]);

	function signInWithPasskey() {
		if (!available || (active.current && !active.current.identifier)) return;
		cancelAutofill();
		const attempt = { controller: new AbortController() };
		active.current = attempt;
		setBusy(true);
		setError("");
		void authenticate(attempt);
	}

	return { identifierRef, cancelAutofill, signInWithPasskey, busy, error };
}

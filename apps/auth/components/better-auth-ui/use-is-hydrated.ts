// Adapted from Better Auth UI official radix-nova registry (MIT). See ATTRIBUTION.md.
"use client";

import { useSyncExternalStore } from "react";

/**
 * Returns `true` once the component is mounted on the client (hydrated) and
 * `false` while rendering on the server, so client-only reads (e.g.
 * `sessionStorage`) stay safe during SSR.
 *
 * @returns Whether the component has hydrated on the client.
 */
export function useIsHydrated() {
	const subscribe = () => () => {};
	return useSyncExternalStore(
		subscribe,
		() => true,
		() => false,
	);
}

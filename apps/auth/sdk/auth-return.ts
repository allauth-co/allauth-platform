"use client";

import { useEffect, useState } from "react";
import { appPath, proxyBasePath } from "./helpers";

const localOrigin = "https://allauth.invalid";

/** Validate an untrusted local return destination, including encoded API/proxy path aliases. */
export function safeAuthReturnTo(value: unknown, basePath = "/api/allauth"): string | undefined {
	if (typeof value !== "string" || !value || value.length > 2048) return;
	try {
		const path = appPath(value);
		if (path.length > 2048 || !path.startsWith("/") || path.startsWith("//")) return;
		const target = new URL(path, localOrigin);
		if (target.origin !== localOrigin) return;
		let inspect = value;
		for (let depth = 0; depth < 4; depth++) {
			if (/[\\\u0000-\u001f\u007f]/.test(inspect)) return;
			let decoded: string;
			try { decoded = decodeURIComponent(inspect); } catch { break; }
			if (decoded === inspect) break;
			inspect = decoded;
		}
		if (/[\\\u0000-\u001f\u007f]/.test(inspect)) return;
		let pathname = target.pathname;
		for (let depth = 0; depth < 4; depth++) {
			const decoded = decodeURIComponent(pathname);
			if (decoded === pathname) break;
			pathname = decoded;
			if (depth === 3 && /%[a-f\d]{2}/i.test(pathname)) return;
		}
		if (!pathname.startsWith("/") || pathname.startsWith("//") || /[\\?#\u0000-\u0020\u007f]/.test(pathname)) return;
		const normalized = new URL(pathname, localOrigin);
		if (normalized.origin !== localOrigin) return;
		const lower = normalized.pathname.toLowerCase();
		const proxy = proxyBasePath(basePath).toLowerCase();
		if (lower === "/api" || lower.startsWith("/api/") || lower === proxy || lower.startsWith(`${proxy}/`)) return;
		return path;
	} catch { return; }
}

/** Explicit component destinations take precedence; invalid queries use the configured fallback. */
export function resolveAuthReturnTo(explicit: string | undefined, query: unknown, fallback: string, basePath = "/api/allauth"): { targetPath: string; intent?: string } {
	if (explicit != null) {
		const targetPath = appPath(explicit);
		return { targetPath, intent: targetPath };
	}
	const intent = safeAuthReturnTo(query, basePath);
	return { targetPath: intent ?? appPath(fallback), ...(intent ? { intent } : {}) };
}

/** Carry an already checked destination through a local link, preserving other query fields and its hash. */
export function withAuthReturnTo(path: string, intent?: string): string {
	const local = appPath(path);
	if (!intent) return local;
	const url = new URL(local, localOrigin);
	url.searchParams.set("returnTo", appPath(intent));
	return url.pathname + url.search + url.hash;
}

/** Read browser return intent after hydration, without storing it or changing the initial server markup. */
export function useAuthReturnTo(explicit: string | undefined, fallback: string, basePath = "/api/allauth") {
	const [query, setQuery] = useState<string | null>(null);
	// Routers can reuse the form after pushState without firing popstate.
	useEffect(() => { setQuery(browserReturnQuery()); });
	useEffect(() => {
		const read = () => setQuery(browserReturnQuery());
		window.addEventListener("popstate", read);
		return () => window.removeEventListener("popstate", read);
	}, []);
	return resolveAuthReturnTo(explicit, query, fallback, basePath);
}

function browserReturnQuery(): string | null {
	const params = new URLSearchParams(window.location.search);
	return params.get("returnTo") ?? (params.get("challenge") === "two-factor" ? params.get("callbackUrl") : null);
}

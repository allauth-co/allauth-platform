import { createInterface } from "node:readline/promises";
import { createClient, fetchJSON, normalizeBaseURL } from "./client.js";
import {
	credentialFilePath,
	removeCredentials,
	saveCredentials,
	validateCookie,
} from "./credentials.js";
import { publicError } from "./errors.js";

export interface LoginOptions {
	baseURL?: string;
	email?: string;
	credentialsFile?: string;
	fetch?: typeof globalThis.fetch;
	prompt?: (label: string, secret?: boolean) => Promise<string>;
}

/** Prompt through the terminal; passwords and MFA codes never echo or enter process arguments. */
export async function terminalPrompt(
	label: string,
	secret = false,
): Promise<string> {
	if (!process.stdin.isTTY || !process.stderr.isTTY)
		throw publicError(
			"AllAuth login requires an interactive terminal. Do not put passwords in command arguments.",
		);
	if (!secret) {
		const terminal = createInterface({
			input: process.stdin,
			output: process.stderr,
		});
		try {
			return await terminal.question(label);
		} finally {
			terminal.close();
		}
	}
	process.stderr.write(label);
	const previousRaw = process.stdin.isRaw;
	process.stdin.setRawMode(true);
	process.stdin.resume();
	try {
		return await new Promise<string>((resolve, reject) => {
			let value = "";
			const decoder = new TextDecoder();
			const finish = (error?: Error) => {
				process.stdin.removeListener("data", onData);
				process.stdin.removeListener("end", onEnd);
				process.stdin.removeListener("error", onError);
				process.stderr.write("\n");
				if (error) reject(error);
				else resolve(value);
			};
			const onEnd = () =>
				finish(publicError("AllAuth login input ended before completion."));
			const onError = () =>
				finish(publicError("AllAuth login terminal input failed."));
			const onData = (chunk: Uint8Array) => {
				for (const character of decoder.decode(chunk, { stream: true })) {
					if (character === "\u0003" || character === "\u0004") {
						finish(publicError("AllAuth login was cancelled."));
						return;
					}
					if (character === "\r" || character === "\n") {
						finish();
						return;
					}
					if (character === "\u007f" || character === "\b")
						value = [...value].slice(0, -1).join("");
					else if (character >= " " && value.length < 4096) value += character;
				}
			};
			process.stdin.on("data", onData);
			process.stdin.once("end", onEnd);
			process.stdin.once("error", onError);
		});
	} finally {
		process.stdin.setRawMode(previousRaw);
		process.stdin.pause();
	}
}

/** Merge response cookies into an origin-local jar, honoring explicit expiry/deletion. */
export function updateCookieJar(
	jar: Map<string, string>,
	headers: Headers,
): void {
	const setCookies =
		typeof headers.getSetCookie === "function"
			? headers.getSetCookie()
			: (headers.get("set-cookie") || "").split(/,(?=\s*[^;,\s]+=)/);
	for (const cookie of setCookies) {
		const [pair, ...attributes] = cookie.split(";");
		if (!pair) continue;
		const separator = pair.indexOf("=");
		if (separator < 1) continue;
		const name = pair.slice(0, separator).trim();
		const value = pair.slice(separator + 1).trim();
		if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name)) continue;
		const fields = new Map(
			attributes.map((attribute) => {
				const [key, ...parts] = attribute.trim().split("=");
				return [key!.toLowerCase(), parts.join("=")] as const;
			}),
		);
		const maxAge = fields.get("max-age");
		const expires = fields.get("expires");
		const deleted =
			maxAge !== undefined
				? Number(maxAge) <= 0
				: Boolean(expires && new Date(expires).getTime() <= Date.now());
		if (!value || deleted) jar.delete(name);
		else {
			validateCookie(`${name}=${value}`);
			jar.set(name, value);
		}
	}
}

function jarHeader(jar: Map<string, string>): string {
	return [...jar].map(([name, value]) => `${name}=${value}`).join("; ");
}
function isMFA(value: unknown): boolean {
	return Boolean(
		value &&
			typeof value === "object" &&
			"twoFactorRedirect" in value &&
			value.twoFactorRedirect === true,
	);
}

/** Keep an accidentally entered code hidden and allow correction without spending the device grant. */
export async function promptMFAMethod(
	prompt: NonNullable<LoginOptions["prompt"]>,
): Promise<"totp" | "recovery"> {
	for (let attempt = 0; attempt < 3; attempt++) {
		const label =
			attempt === 0
				? "MFA method: press Enter for authenticator, or type recovery (code comes next): "
				: "Choose the method first, not the code. Press Enter for authenticator, or type recovery: ";
		const method = (await prompt(label, true)).trim().toLowerCase() || "totp";
		if (method === "totp" || method === "recovery") return method;
	}
	throw publicError(
		"Choose totp or recovery before entering a code. No credentials were saved.",
	);
}

/** Sign in through the native root email/password and MFA APIs, persisting only a verified management session. */
export async function login(options: LoginOptions = {}): Promise<void> {
	const baseURL = normalizeBaseURL(options.baseURL);
	const credentialsFile = credentialFilePath(options.credentialsFile);
	const prompt = options.prompt || terminalPrompt;
	const email = (options.email || (await prompt("AllAuth email: "))).trim();
	const password = await prompt("Password: ", true);
	if (
		!email ||
		email.length > 320 ||
		!email.includes("@") ||
		!password ||
		password.length > 4096
	)
		throw publicError("Enter your AllAuth root account email and password.");
	const jar = new Map<string, string>();
	const post = (path: string, body: unknown) =>
		fetchJSON(
			new URL(path, baseURL),
			{
				method: "POST",
				headers: {
					Accept: "application/json",
					"Content-Type": "application/json",
					Origin: baseURL,
					...(jar.size ? { Cookie: jarHeader(jar) } : {}),
				},
				body: JSON.stringify(body),
			},
			{ fetch: options.fetch },
			(headers) => updateCookieJar(jar, headers),
		);
	let result = await post("/api/auth/sign-in/email", {
		email,
		password,
		rememberMe: true,
	});
	if (isMFA(result)) {
		const method = await promptMFAMethod(prompt);
		const code = (
			await prompt(
				method === "recovery"
					? "Recovery code (used once): "
					: "Authenticator code: ",
				true,
			)
		).trim();
		if (!code || code.length > 128)
			throw publicError("Enter one authenticator or recovery code.");
		result = await post(
			method === "recovery"
				? "/api/auth/two-factor/verify-backup-code"
				: "/api/auth/two-factor/verify-totp",
			{ code, trustDevice: false },
		);
	}
	if (isMFA(result) || !jar.size)
		throw publicError(
			"AllAuth did not issue a complete session. No credentials were saved.",
		);
	const cookie = validateCookie(jarHeader(jar));
	// This root-only route checks admission, bans, verified email, and the stored platform session.
	const client = await createClient({ baseURL, cookie, fetch: options.fetch });
	await client.request({ method: "GET", path: "/api/workspaces" });
	await saveCredentials(baseURL, cookie, credentialsFile);
}

/** Remove the saved local credential for one origin; remote sessions remain subject to normal revocation. */
export async function logout(
	options: Pick<LoginOptions, "baseURL" | "credentialsFile"> = {},
): Promise<void> {
	await removeCredentials(
		normalizeBaseURL(options.baseURL),
		credentialFilePath(options.credentialsFile),
	);
}

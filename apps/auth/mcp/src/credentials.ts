import { publicError } from "./errors.js";
import { constants } from "node:fs";
import { lstat, mkdir, open, rename, unlink } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, isAbsolute, join } from "node:path";
import { randomUUID } from "node:crypto";

interface StoredSession { cookie: string; updatedAt: string }
interface CredentialStore { version: 1; sessions: Record<string, StoredSession> }
const maxCredentialBytes = 1024 * 1024;

/** Resolve the private, origin-indexed credential store without reading its contents. */
export function credentialFilePath(explicit?: string): string {
	const result = explicit || process.env.ALLAUTH_CREDENTIALS_FILE || join(process.env.XDG_CONFIG_HOME || join(homedir(), ".config"), "allauth", "credentials.json");
	if (!isAbsolute(result)) throw publicError("The AllAuth credential file path must be absolute.");
	return result;
}

/** Validate an opaque Cookie request header; credentials are never included in failures. */
export function validateCookie(value: string): string {
	const cookie = value.trim();
	if (!cookie || cookie.length > 16384 || /[\x00-\x1f\x7f]/.test(cookie) || !cookie.split(";").every((pair) => /^\s*[^=;\s]+=[^;]*$/.test(pair))) throw publicError("The AllAuth cookie must be a nonempty Cookie request header.");
	return cookie;
}

/** Read a regular private file without following symbolic links. */
export async function readPrivateFile(path: string): Promise<string> {
	if (!isAbsolute(path)) throw publicError("The AllAuth credential file path must be absolute.");
	let handle;
	try {
		handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
		const info = await handle.stat();
		if (!info.isFile() || info.size > maxCredentialBytes) throw publicError("invalid-file");
		if (process.platform !== "win32" && ((info.mode & 0o077) !== 0 || (process.getuid && info.uid !== process.getuid()))) throw publicError("unsafe-permissions");
		return await handle.readFile({ encoding: "utf8" });
	} catch (error) {
		if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") throw error;
		throw publicError("AllAuth credentials must be an owned, regular private file (chmod 600), without symbolic links.");
	} finally { await handle?.close(); }
}

async function readStore(path: string): Promise<CredentialStore> {
	let content: string;
	try { content = await readPrivateFile(path); }
	catch (error) {
		if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return { version: 1, sessions: {} };
		throw error;
	}
	try {
		const store: unknown = JSON.parse(content);
		if (!store || typeof store !== "object" || !("version" in store) || store.version !== 1 || !("sessions" in store) || !store.sessions || typeof store.sessions !== "object" || Array.isArray(store.sessions)) throw publicError("Invalid credential data.");
		const sessions: Record<string, StoredSession> = {};
		for (const [origin, value] of Object.entries(store.sessions)) {
			if (!value || typeof value !== "object" || !("cookie" in value) || typeof value.cookie !== "string" || !("updatedAt" in value) || typeof value.updatedAt !== "string") throw publicError("Invalid credential data.");
			Object.defineProperty(sessions, origin, { value: { cookie: validateCookie(value.cookie), updatedAt: value.updatedAt }, enumerable: true, configurable: true });
		}
		return { version: 1, sessions };
	} catch { throw publicError("The AllAuth credential store is invalid. Restore it or log in using a new credential file."); }
}

/** Load only the saved session belonging to the exact configured origin. */
export async function loadCredentials(origin: string, path = credentialFilePath()): Promise<string | undefined> {
	const sessions = (await readStore(path)).sessions;
	return Object.hasOwn(sessions, origin) ? sessions[origin]?.cookie : undefined;
}

async function writeStore(path: string, store: CredentialStore): Promise<void> {
	await mkdir(dirname(path), { recursive: true, mode: 0o700 });
	const directory = await lstat(dirname(path));
	if (!directory.isDirectory() || directory.isSymbolicLink() || (process.platform !== "win32" && ((directory.mode & 0o022) !== 0 || (process.getuid && directory.uid !== process.getuid())))) throw publicError("The AllAuth credential directory must be owned, writable only by you, and not a symbolic link.");
	const temporary = `${path}.${randomUUID()}.tmp`;
	try {
		const handle = await open(temporary, "wx", 0o600);
		try { await handle.writeFile(`${JSON.stringify(store, null, 2)}\n`, "utf8"); await handle.sync(); }
		finally { await handle.close(); }
		await rename(temporary, path);
	} finally { await unlink(temporary).catch(() => undefined); }
}

/** Atomically save a complete management session, indexed by its exact origin. */
export async function saveCredentials(origin: string, cookie: string, path = credentialFilePath()): Promise<void> {
	const store = await readStore(path);
	Object.defineProperty(store.sessions, origin, { value: { cookie: validateCookie(cookie), updatedAt: new Date().toISOString() }, enumerable: true, configurable: true });
	await writeStore(path, store);
}

/** Forget this origin's local session without claiming to revoke it remotely. */
export async function removeCredentials(origin: string, path = credentialFilePath()): Promise<void> {
	const store = await readStore(path);
	if (!Object.hasOwn(store.sessions, origin)) return;
	delete store.sessions[origin];
	await writeStore(path, store);
}

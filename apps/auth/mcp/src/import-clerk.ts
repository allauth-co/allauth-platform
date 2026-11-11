import { constants } from "node:fs";
import { lstat, mkdir, open, realpath } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import * as z from "zod";
import { tools } from "./catalog.js";
import type { ToolRequest } from "./catalog.js";
import { createClient } from "./client.js";
import { readPrivateFile } from "./credentials.js";
import { publicError, publicErrorMessage } from "./errors.js";
import { environmentFlag } from "./server.js";

interface ImportClerkArguments { project: string; input: string; out: string; apply?: boolean; baseURL?: string }
interface ImportClerkOptions extends ImportClerkArguments {
	readOnly?: boolean;
	allowSensitive?: boolean;
	request?: (operation: ToolRequest) => Promise<unknown>;
	stdout?: (text: string) => void;
}
const identifier = z.string().regex(/^[A-Za-z0-9_.:-]{1,160}$/);
const resultSchema = z.object({
	project: z.string(), projectId: z.uuid(), sourceInstance: identifier, dryRun: z.boolean(),
	created: z.number().int().nonnegative(), existing: z.number().int().nonnegative(), conflicts: z.number().int().nonnegative(),
	users: z.array(z.object({
		sourceUserId: identifier, sourceUpdatedAt: z.iso.datetime({ offset: true }).nullable(), userId: identifier.optional(),
		status: z.enum(["would_create", "created", "existing", "conflict"]),
		reason: z.enum(["email_conflict", "provider_conflict", "source_conflict", "source_changed", "mfa_unsupported", "write_conflict"]).optional(),
	})).min(1).max(100),
});

/** Parse only explicit file-based import options; payloads and credentials are never CLI values. */
export function parseImportClerkArguments(arguments_: string[]): ImportClerkArguments {
	const values = new Map<string, string>(); let apply = false;
	for (let index = 0; index < arguments_.length; index++) {
		const flag = arguments_[index]!;
		if (flag === "--apply" && !apply) { apply = true; continue; }
		if (!["--project", "--input", "--out", "--url"].includes(flag) || values.has(flag)) throw publicError("Unknown or repeated import-clerk option. Use --help.");
		const value = arguments_[++index];
		if (!value || value.startsWith("-")) throw publicError("Each import-clerk option requires its value. Use --help.");
		values.set(flag, value);
	}
	if (!["--project", "--input", "--out"].every((flag) => values.has(flag))) throw publicError("import-clerk requires --project, --input and --out. Use --help.");
	return { project: values.get("--project")!, input: values.get("--input")!, out: values.get("--out")!, apply, ...(values.has("--url") ? { baseURL: values.get("--url")! } : {}) };
}

/** Canonical ancestors prevent symlinked directories from hiding a Git checkout. */
async function requireOutsideRepository(canonicalPath: string, directory = false): Promise<void> {
	let parent = directory ? canonicalPath : dirname(canonicalPath);
	for (;;) {
		try { await lstat(join(parent, ".git")); throw publicError("Keep Clerk import input and result files outside every Git repository."); }
		catch (error) {
			if (publicErrorMessage(error)) throw error;
			if (!error || typeof error !== "object" || !("code" in error) || error.code !== "ENOENT") throw publicError("The private import directory could not be checked.");
		}
		const next = dirname(parent); if (next === parent) return; parent = next;
	}
}

/** Import one private batch through the named management operation, with no payload logging. */
export async function importClerkBatch(options: ImportClerkOptions) {
	const readOnly = options.readOnly ?? environmentFlag("ALLAUTH_READ_ONLY");
	const allowSensitive = options.allowSensitive ?? environmentFlag("ALLAUTH_ALLOW_SENSITIVE");
	if (readOnly) throw publicError("The connection is read-only; import-clerk is a privileged POST operation, including dry runs.");
	if (!allowSensitive) throw publicError("Sensitive operations are disabled. Set ALLAUTH_ALLOW_SENSITIVE=true for private Clerk import files.");
	const operation = tools.find((tool) => tool.name === "allauth_users_import_clerk");
	if (!operation || operation.readOnly || !operation.sensitive) throw publicError("The supported Clerk import operation is unavailable.");
	let input: unknown;
	try {
		const filename = resolve(options.input);
		await requireOutsideRepository(await realpath(filename));
		input = JSON.parse(await readPrivateFile(filename)) as unknown;
	} catch (error) { throw publicError(publicErrorMessage(error) ?? "The Clerk import input must be valid JSON in an owned, private regular file outside the repository."); }
	if (!input || typeof input !== "object" || Array.isArray(input)) throw publicError("The Clerk import input must be one batch object.");
	if ("project" in input && input.project !== options.project) throw publicError("The input project conflicts with the exact --project selection.");
	let request: ToolRequest;
	try {
		// Validate the file before overriding dryRun so malformed file flags are not ignored.
		const parsed = operation.inputSchema.parse({ ...input, project: options.project });
		request = operation.buildRequest({ ...parsed, dryRun: options.apply !== true });
	} catch { throw publicError("The Clerk import input does not match the supported batch schema."); }
	const body = request.body as { sourceInstance: string; dryRun: boolean; users: Array<{ sourceUserId: string; updatedAt?: string }> };
	const originals = new Map(body.users.map((user) => [user.sourceUserId, user.updatedAt ? new Date(user.updatedAt).toISOString() : null]));
	if (originals.size !== body.users.length) throw publicError("The Clerk import input contains duplicate source identities.");
	const perform = options.request ?? (await createClient({ baseURL: options.baseURL })).request;
	const absoluteOutput = resolve(options.out);
	let handle;
	try {
		await mkdir(dirname(absoluteOutput), { recursive: true, mode: 0o700 });
		const parent = await realpath(dirname(absoluteOutput));
		await requireOutsideRepository(parent, true);
		handle = await open(join(parent, basename(absoluteOutput)), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW || 0), 0o600);
	} catch (error) { throw publicError(publicErrorMessage(error) ?? "The private result file must be new and writable. Existing files and symbolic links are never overwritten."); }
	try {
		let result: z.output<typeof resultSchema>;
		try {
			const raw = await perform(request);
			const checked = resultSchema.safeParse(raw);
			if (!checked.success) throw publicError("AllAuth returned an invalid import result. Read the selected environment before retrying.");
			result = checked.data;
			if (result.project !== options.project || result.sourceInstance !== body.sourceInstance || result.dryRun !== body.dryRun || result.users.length !== originals.size || new Set(result.users.map((user) => user.sourceUserId)).size !== originals.size ||
				result.created !== result.users.filter((user) => user.status === "created").length || result.existing !== result.users.filter((user) => user.status === "existing").length || result.conflicts !== result.users.filter((user) => user.status === "conflict").length ||
				result.users.some((user) => !originals.has(user.sourceUserId) || user.sourceUpdatedAt !== originals.get(user.sourceUserId) || (user.status !== "conflict" && !user.userId) || (user.status === "conflict" && !user.reason) || (user.status === "created" && body.dryRun) || (user.status === "would_create" && !body.dryRun))) throw publicError("AllAuth returned a mismatched import result. Read the selected environment before retrying.");
		} catch (error) {
			await handle.writeFile(`${JSON.stringify({ complete: false, outcome: "unknown", project: options.project, sourceInstance: body.sourceInstance, dryRun: body.dryRun })}\n`, "utf8");
			await handle.sync();
			throw publicError(publicErrorMessage(error) ?? "The Clerk import outcome could not be verified. A private incomplete result was saved; read the selected environment before retrying.");
		}
		// The result schema projects only IDs, timestamps, counts and safe status codes.
		await handle.writeFile(`${JSON.stringify(result, null, 2)}\n`, "utf8"); await handle.sync();
		const summary = { dryRun: result.dryRun, accounts: result.users.length, created: result.created, existing: result.existing, conflicts: result.conflicts };
		(options.stdout ?? ((text: string) => process.stdout.write(text)))(`${JSON.stringify(summary)}\n`);
		return summary;
	} finally { await handle.close(); }
}

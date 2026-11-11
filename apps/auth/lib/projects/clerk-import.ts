import { createHash } from "node:crypto";
import type { GenericEndpointContext } from "@better-auth/core";
import { getCurrentAdapter, runWithTransaction } from "@better-auth/core/context";
import type { DBTransactionAdapter } from "@better-auth/core/db/adapter";
import { createAuthEndpoint } from "better-auth/api";
import * as z from "zod";
import { isClerkBcryptHash } from "../clerk-password";
import type { ControlEventInput, ControlPrincipal } from "../control/types";

const sourceId = z.string().regex(/^[A-Za-z0-9_.:-]{1,160}$/);
const metadata = z.record(z.string(), z.json());
const socialAccount = z.object({ provider: z.enum(["google", "apple"]), subject: z.string().min(1).max(255) }).strict();
export const clerkImportUser = z.object({
	sourceUserId: sourceId,
	email: z.email().max(320).transform((value) => value.toLowerCase()),
	emailVerified: z.boolean(), name: z.string().trim().min(1).max(100),
	image: z.url().max(2048).refine((value) => { const url = new URL(value); return url.protocol === "https:" && !url.username && !url.password; }, "Use an HTTPS profile image.").optional(),
	createdAt: z.iso.datetime({ offset: true }).optional(), updatedAt: z.iso.datetime({ offset: true }).optional(),
	passwordHash: z.string().max(256).refine(isClerkBcryptHash, "Unsupported bcrypt encoding or work factor.").optional(),
	passwordHasher: z.literal("bcrypt").optional(),
	socialAccounts: z.array(socialAccount).max(10).default([]),
	banned: z.boolean().default(false), locked: z.boolean().default(false), twoFactorEnabled: z.boolean().default(false),
	publicMetadata: metadata.optional(), privateMetadata: metadata.optional(),
}).strict().superRefine((value, context) => {
	if (Boolean(value.passwordHash) !== Boolean(value.passwordHasher)) context.addIssue({ code: "custom", message: "Supply passwordHash and passwordHasher together.", path: ["passwordHasher"] });
	if (value.privateMetadata && Object.hasOwn(value.privateMetadata, "allauthClerkMigration")) context.addIssue({ code: "custom", message: "Migration provenance is server-owned.", path: ["privateMetadata"] });
	if (value.createdAt && value.updatedAt && new Date(value.createdAt) > new Date(value.updatedAt)) context.addIssue({ code: "custom", message: "updatedAt must not precede createdAt.", path: ["updatedAt"] });
	const subjects = value.socialAccounts.map((account) => JSON.stringify([account.provider, account.subject]));
	if (new Set(subjects).size !== subjects.length) context.addIssue({ code: "custom", message: "Duplicate social account.", path: ["socialAccounts"] });
});
export const clerkImportBody = z.object({ sourceInstance: sourceId, dryRun: z.boolean().default(true), users: z.array(clerkImportUser).min(1).max(100) }).strict().superRefine((value, context) => {
	if (new Set(value.users.map((user) => user.sourceUserId)).size !== value.users.length) context.addIssue({ code: "custom", message: "Duplicate source user in batch.", path: ["users"] });
	if (new TextEncoder().encode(JSON.stringify(value)).byteLength > 1024 * 1024) context.addIssue({ code: "custom", message: "Import batches must not exceed 1 MiB." });
});
type ImportUser = z.output<typeof clerkImportUser>;
type Conflict = "email_conflict" | "provider_conflict" | "source_conflict" | "source_changed" | "mfa_unsupported" | "write_conflict";
interface ImportResult { sourceUserId: string; sourceUpdatedAt: string | null; userId?: string; status: "would_create" | "created" | "existing" | "conflict"; reason?: Conflict }
interface StoredUser { id: string; email: string; privateMetadata?: Record<string, unknown> | null }

/** Canonical JSON avoids source drift caused only by object key order. */
function canonical(value: unknown): string {
	if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
	if (value !== null && typeof value === "object") return `{${Object.entries(value).filter(([, item]) => item !== undefined).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`).join(",")}}`;
	return JSON.stringify(value) ?? "null";
}
const digest = (value: string) => createHash("sha256").update(value).digest("hex");

/** Deterministic IDs enforce repeat safety with the realm's existing primary keys. */
function importedId(projectId: string, sourceInstance: string, sourceUserId: string): string {
	return `clerk_${digest(JSON.stringify([projectId, sourceInstance, sourceUserId]))}`;
}

async function inspect(adapter: DBTransactionAdapter, user: ImportUser, userId: string, sourceInstance: string, fingerprint: string): Promise<Conflict | "existing" | undefined> {
	const existing = await adapter.findOne<StoredUser>({ model: "user", where: [{ field: "id", value: userId }] });
	if (existing) {
		const provenance = existing.privateMetadata?.allauthClerkMigration;
		if (!provenance || typeof provenance !== "object" || !("sourceInstance" in provenance) || !("sourceUserId" in provenance) || provenance.sourceInstance !== sourceInstance || provenance.sourceUserId !== user.sourceUserId) return "source_conflict";
		return "fingerprint" in provenance && provenance.fingerprint === fingerprint ? "existing" : "source_changed";
	}
	if (user.twoFactorEnabled) return "mfa_unsupported";
	if (await adapter.findOne({ model: "user", where: [{ field: "email", value: user.email }] })) return "email_conflict";
	for (const account of user.socialAccounts) {
		if (await adapter.findOne({ model: "account", where: [{ field: "providerId", value: account.provider }, { field: "accountId", value: account.subject }] })) return "provider_conflict";
	}
	return undefined;
}

/** A privileged, exact-realm import; it never links an existing account by email. */
export function clerkImportEndpoint(options: {
	projectId: string;
	projectSlug?: string;
	authorize: (ctx: GenericEndpointContext) => Promise<ControlPrincipal>;
	recordEvent: (ctx: GenericEndpointContext, event: ControlEventInput) => Promise<void>;
}) {
	return createAuthEndpoint("/project-admin/import-clerk-users", { method: "POST", requireHeaders: true, body: clerkImportBody }, async (ctx) => {
		const actor = await options.authorize(ctx);
		const results: ImportResult[] = [];
		const seenEmails = new Set<string>();
		const seenProviders = new Set<string>();
		for (const user of ctx.body.users) {
			const userId = importedId(options.projectId, ctx.body.sourceInstance, user.sourceUserId);
			const fingerprint = digest(canonical(user));
			const result = (status: ImportResult["status"], reason?: Conflict): ImportResult => ({ sourceUserId: user.sourceUserId, sourceUpdatedAt: user.updatedAt ? new Date(user.updatedAt).toISOString() : null, ...(status === "conflict" ? {} : { userId }), status, ...(reason ? { reason } : {}) });
			const providerKeys = user.socialAccounts.map((account) => JSON.stringify([account.provider, account.subject]));
			if (seenEmails.has(user.email) || providerKeys.some((key) => seenProviders.has(key))) {
				results.push(result("conflict", seenEmails.has(user.email) ? "email_conflict" : "provider_conflict")); continue;
			}
			const process = async (): Promise<ImportResult> => {
				const adapter = await getCurrentAdapter(ctx.context.adapter);
				const status = await inspect(adapter, user, userId, ctx.body.sourceInstance, fingerprint);
				if (status) return status === "existing" ? result("existing") : result("conflict", status);
				if (ctx.body.dryRun) return result("would_create");
				const now = new Date();
				const createdAt = user.createdAt ? new Date(user.createdAt) : now;
				const updatedAt = user.updatedAt ? new Date(user.updatedAt) : now;
				await adapter.create({ model: "user", forceAllowId: true, data: { id: userId, name: user.name, email: user.email, emailVerified: user.emailVerified, ...(user.image ? { image: user.image } : {}), createdAt, updatedAt, role: "user", banned: user.banned || user.locked, ...(user.banned || user.locked ? { banReason: "Restricted in source identity provider" } : {}), ...(user.publicMetadata ? { publicMetadata: user.publicMetadata } : {}), privateMetadata: { ...user.privateMetadata, allauthClerkMigration: { version: 1, sourceInstance: ctx.body.sourceInstance, sourceUserId: user.sourceUserId, fingerprint, sourceUpdatedAt: user.updatedAt || null, banned: user.banned, locked: user.locked } } } });
				if (user.passwordHash) await adapter.create({ model: "account", forceAllowId: true, data: { id: `clerk_credential_${digest(userId)}`, providerId: "credential", accountId: userId, userId, password: user.passwordHash, createdAt, updatedAt } });
				for (const account of user.socialAccounts) await adapter.create({ model: "account", forceAllowId: true, data: { id: `clerk_social_${digest(JSON.stringify([account.provider, account.subject]))}`, providerId: account.provider, accountId: account.subject, userId, createdAt, updatedAt } });
				// A dedicated administrative event suppresses new-user onboarding consumers.
				await options.recordEvent(ctx, { type: "admin.clerk-import", outcome: "success", actorId: actor.user.id, userId, targetId: userId, metadata: { path: ctx.path, signal: "clerk-import", version: 1 } });
				return result("created");
			};
			let entry: ImportResult;
			try { entry = ctx.body.dryRun ? await process() : await runWithTransaction(ctx.context.adapter, process); }
			catch {
				// Driver errors can contain credential-bearing bind values. Return only a safe code.
				entry = result("conflict", "write_conflict");
			}
			results.push(entry);
			if (entry.status !== "conflict") { seenEmails.add(user.email); providerKeys.forEach((key) => seenProviders.add(key)); }
		}
		return ctx.json({ project: options.projectSlug ?? null, projectId: options.projectId, sourceInstance: ctx.body.sourceInstance, dryRun: ctx.body.dryRun, created: results.filter((entry) => entry.status === "created").length, existing: results.filter((entry) => entry.status === "existing").length, conflicts: results.filter((entry) => entry.status === "conflict").length, users: results });
	});
}

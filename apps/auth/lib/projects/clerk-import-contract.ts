import { createHash } from "node:crypto";
import * as z from "zod";
import { isClerkBcryptHash } from "../clerk-password";

const sourceId = z.string().regex(/^[A-Za-z0-9_.:-]{1,160}$/);
const metadata = z.record(z.string(), z.json());
const socialAccount = z
	.object({
		provider: z.enum(["google", "apple"]),
		subject: z.string().min(1).max(255),
	})
	.strict();
export const clerkImportUser = z
	.object({
		sourceUserId: sourceId,
		email: z
			.email()
			.max(320)
			.transform((value) => value.toLowerCase()),
		emailVerified: z.boolean(),
		name: z.string().trim().min(1).max(100),
		image: z
			.url()
			.max(2048)
			.refine((value) => {
				const url = new URL(value);
				return url.protocol === "https:" && !url.username && !url.password;
			}, "Use an HTTPS profile image.")
			.optional(),
		createdAt: z.iso.datetime({ offset: true }).optional(),
		updatedAt: z.iso.datetime({ offset: true }).optional(),
		passwordHash: z
			.string()
			.max(256)
			.refine(isClerkBcryptHash, "Unsupported bcrypt encoding or work factor.")
			.optional(),
		passwordHasher: z.literal("bcrypt").optional(),
		socialAccounts: z.array(socialAccount).max(10).default([]),
		banned: z.boolean().default(false),
		locked: z.boolean().default(false),
		twoFactorEnabled: z.boolean().default(false),
		publicMetadata: metadata.optional(),
		privateMetadata: metadata.optional(),
	})
	.strict()
	.superRefine((value, context) => {
		if (Boolean(value.passwordHash) !== Boolean(value.passwordHasher))
			context.addIssue({
				code: "custom",
				message: "Supply passwordHash and passwordHasher together.",
				path: ["passwordHasher"],
			});
		if (
			value.privateMetadata &&
			Object.hasOwn(value.privateMetadata, "allauthClerkMigration")
		)
			context.addIssue({
				code: "custom",
				message: "Migration provenance is server-owned.",
				path: ["privateMetadata"],
			});
		if (
			value.createdAt &&
			value.updatedAt &&
			new Date(value.createdAt) > new Date(value.updatedAt)
		)
			context.addIssue({
				code: "custom",
				message: "updatedAt must not precede createdAt.",
				path: ["updatedAt"],
			});
		const subjects = value.socialAccounts.map((account) =>
			JSON.stringify([account.provider, account.subject]),
		);
		if (new Set(subjects).size !== subjects.length)
			context.addIssue({
				code: "custom",
				message: "Duplicate social account.",
				path: ["socialAccounts"],
			});
	});
export const clerkImportBody = z
	.object({
		sourceInstance: sourceId,
		dryRun: z.boolean().default(true),
		users: z.array(clerkImportUser).min(1).max(100),
	})
	.strict()
	.superRefine((value, context) => {
		if (
			new Set(value.users.map((user) => user.sourceUserId)).size !==
			value.users.length
		)
			context.addIssue({
				code: "custom",
				message: "Duplicate source user in batch.",
				path: ["users"],
			});
		if (
			new TextEncoder().encode(JSON.stringify(value)).byteLength >
			1024 * 1024
		)
			context.addIssue({
				code: "custom",
				message: "Import batches must not exceed 1 MiB.",
			});
	});
export type ImportUser = z.output<typeof clerkImportUser>;
export type Conflict =
	| "email_conflict"
	| "provider_conflict"
	| "source_conflict"
	| "source_changed"
	| "mfa_unsupported"
	| "write_conflict";
export interface ImportResult {
	sourceUserId: string;
	sourceUpdatedAt: string | null;
	userId?: string;
	status: "would_create" | "created" | "existing" | "conflict";
	reason?: Conflict;
}

/** Canonical JSON avoids source drift caused only by object key order. */
export function canonical(value: unknown): string {
	if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
	if (value !== null && typeof value === "object")
		return `{${Object.entries(value)
			.filter(([, item]) => item !== undefined)
			.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
			.map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`)
			.join(",")}}`;
	return JSON.stringify(value) ?? "null";
}
export const digest = (value: string) =>
	createHash("sha256").update(value).digest("hex");

/** Deterministic IDs enforce repeat safety with the realm's existing primary keys. */
export function importedId(
	projectId: string,
	sourceInstance: string,
	sourceUserId: string,
): string {
	return `clerk_${digest(JSON.stringify([projectId, sourceInstance, sourceUserId]))}`;
}

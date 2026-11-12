import * as z from "zod";

const email = z
	.email()
	.max(320)
	.refine((value) => value === value.trim().toLowerCase());
const aliasesSchema = z.record(
	email,
	z.string().regex(/^[A-Za-z0-9_-]{1,160}$/),
);

export type ProjectEmailAliasMap = Readonly<Record<string, string>>;

/** A separate server variable keeps each realm's verified migration aliases private and isolated. */
export function projectEmailAliasVariable(project: string): string {
	if (!/^[a-z][a-z0-9-]{1,47}$/.test(project))
		throw new Error("An exact project is required for email aliases.");
	return `ALLAUTH_PROJECT_${project.replaceAll("-", "_").toUpperCase()}_EMAIL_ALIASES`;
}

export function parseProjectEmailAliases(raw: string): ProjectEmailAliasMap {
	if (raw.length <= 32768) {
		try {
			const aliases = raw.trim() ? aliasesSchema.parse(JSON.parse(raw)) : {};
			if (Object.keys(aliases).length <= 100) return aliases;
		} catch {
			// The configuration can contain private email addresses and account IDs.
		}
	}
	throw new Error("The project email alias configuration is invalid.");
}

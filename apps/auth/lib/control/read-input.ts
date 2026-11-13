import * as z from "zod";

export const controlIdentifier = z.string().trim().min(1).max(160);
const pagination = {
	limit: z.coerce.number().int().min(1).max(100).default(25),
	offset: z.coerce.number().int().min(0).max(100000).default(0),
};
export const controlEventsQuery = z
	.object({
		scope: z.enum(["admin", "organization", "user"]).default("user"),
		organizationId: controlIdentifier.optional(),
		userId: controlIdentifier.optional(),
		type: z
			.string()
			.max(128)
			.regex(/^[a-zA-Z0-9./_-]+$/)
			.optional(),
		outcome: z.enum(["success", "failure", "blocked"]).optional(),
		from: z.iso.datetime({ offset: true }).optional(),
		to: z.iso.datetime({ offset: true }).optional(),
		q: z.string().trim().min(1).max(128).optional(),
		...pagination,
	})
	.strict()
	.refine(
		(value) =>
			!value.from || !value.to || new Date(value.from) <= new Date(value.to),
		{ message: "The start date must precede the end date." },
	)
	.prefault({});

export const controlSessionsQuery = z
	.object({
		userId: controlIdentifier.optional(),
		q: z.string().trim().min(1).max(128).optional(),
		...pagination,
	})
	.strict()
	.prefault({});

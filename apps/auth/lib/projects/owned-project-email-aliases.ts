import type { Pool, PoolClient } from "pg";
import * as z from "zod";
import type { ProjectEmailAliasMap } from "../project-email-alias-config";
import { checkedProjectSchema } from "./validation";

export interface ProjectEmailIdentity {
	email: string;
	userId?: string;
}

export type OwnedProjectEmailAliases = ReturnType<
	typeof createOwnedProjectEmailAliases
>;

export function createOwnedProjectEmailAliases(
	database: Pool,
	schemaName: string,
	configured: ProjectEmailAliasMap = {},
) {
	const schema = checkedProjectSchema(schemaName);
	const email = z.email().max(320);
	const aliases = new Map(Object.entries(configured));

	function reserved(address: string) {
		return aliases.has(address.trim().toLowerCase());
	}

	function normalizeInput(input: unknown) {
		if (
			input &&
			typeof input === "object" &&
			"email" in input &&
			typeof input.email === "string" &&
			reserved(input.email)
		)
			return { ...input, email: input.email.trim().toLowerCase() };
		return input;
	}

	/** Resolve the entered alias only in this schema and keep the immutable owner in the result. */
	async function resolve(
		entered: string,
		client?: PoolClient,
	): Promise<ProjectEmailIdentity | null> {
		const userId = aliases.get(entered);
		if (!userId) return { email: entered };
		const {
			rows: [target],
		} = await (client ?? database).query<{ email: string }>(
			`SELECT target.email FROM "${schema}"."user" target
			 WHERE target.id=$1 AND target."emailVerified" IS TRUE AND NOT EXISTS (
			   SELECT 1 FROM "${schema}"."user" owner WHERE owner.email=$2 AND owner.id<>target.id
			 )${client ? " FOR UPDATE OF target" : ""}`,
			[userId, entered],
		);
		if (!target || !email.safeParse(target.email).success) return null;
		return { email: target.email.toLowerCase(), userId };
	}

	return { reserved, normalizeInput, resolve };
}

import { randomUUID } from "node:crypto";
import { hashPassword } from "better-auth/crypto";
import type { Pool } from "pg";
import * as z from "zod";

const initialAdministrator = z.object({
	email: z.email().transform((value) => value.toLowerCase()),
	name: z.string().trim().min(2).max(100),
	password: z.string().min(12).max(128),
});

/** Initialise an empty self-hosted database without an email-provider dependency. */
export async function initializeSelfHostedAdministrator(database: Pool, mode: string | undefined, input: unknown) {
	if (mode !== "self-hosted") throw new Error("Initial administrator creation is only available in explicit self-hosted mode.");
	const value = initialAdministrator.parse(input);
	const password = await hashPassword(value.password);
	const client = await database.connect();
	try {
		await client.query("BEGIN");
		await client.query("SELECT pg_advisory_xact_lock(661147373)");
		if ((await client.query('SELECT id FROM public."user" LIMIT 1')).rows.length) throw new Error("Initialisation requires an empty user directory. Use db:bootstrap-admin for an existing verified account.");
		const id = randomUUID();
		await client.query('INSERT INTO public."user" (id,name,email,"emailVerified",role) VALUES ($1,$2,$3,true,\'admin\')', [id, value.name, value.email]);
		await client.query('INSERT INTO public.account (id,"accountId","providerId","userId",password,"createdAt","updatedAt") VALUES ($1,$2,\'credential\',$2,$3,NOW(),NOW())', [randomUUID(), id, password]);
		await client.query('INSERT INTO public."allauthAudit" (id,"actorId",action,"targetId","createdAt") VALUES ($1,\'self-host-initialisation\',\'administrator.initialised\',$2,NOW())', [randomUUID(), id]);
		await client.query('INSERT INTO public."allauthEvent" (id,type,outcome,"actorId","targetId","createdAt") VALUES ($1,\'administrator.initialised\',\'success\',\'self-host-initialisation\',$2,NOW())', [randomUUID(), id]);
		await client.query("COMMIT");
		return { id };
	} catch (error) {
		await client.query("ROLLBACK");
		throw error;
	} finally { client.release(); }
}

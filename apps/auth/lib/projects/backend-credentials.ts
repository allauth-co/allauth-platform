// cspell:words aabk
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { APIError } from "better-auth";
import * as z from "zod";
import type { WorkspaceDatabase } from "../workspaces/authorization";

export const backendCredentialInput = z
	.object({
		name: z.string().trim().min(1).max(100),
		expiresInDays: z.number().int().min(1).max(90).default(90),
	})
	.strict();
const hash = (key: string) => createHash("sha256").update(key).digest("hex");
const projection = 'id,name,scope,version,"expiresAt","revokedAt","createdAt"';

/** Service credentials have no user, cookie, platform or write authority. */
export function backendCredentialRepository(database: WorkspaceDatabase) {
	return {
		async list(projectId: string) {
			return {
				credentials: (
					await database.query(
						`SELECT ${projection} FROM public."allauthProjectBackendCredential" WHERE "projectId"=$1 ORDER BY "createdAt",id`,
						[projectId],
					)
				).rows,
			};
		},
		async create(projectId: string, actorId: string, raw: unknown) {
			const input = backendCredentialInput.parse(raw);
			const id = randomUUID();
			const key = `aabk_${id}_${randomBytes(32).toString("base64url")}`;
			const credential = (
				await database.query(
					`INSERT INTO public."allauthProjectBackendCredential" (id,"projectId",name,scope,"keyHash","expiresAt","createdBy") VALUES ($1,$2,$3,'directory:read',$4,NOW()+$5*INTERVAL '1 day',$6) RETURNING ${projection}`,
					[id, projectId, input.name, hash(key), input.expiresInDays, actorId],
				)
			).rows[0];
			return { credential, key };
		},
		async revoke(projectId: string, id: string) {
			z.uuid().parse(id);
			const result = await database.query(
				`UPDATE public."allauthProjectBackendCredential" SET "revokedAt"=COALESCE("revokedAt",NOW()) WHERE id=$1 AND "projectId"=$2 RETURNING ${projection}`,
				[id, projectId],
			);
			if (!result.rows[0]) throw new APIError("NOT_FOUND");
			return { credential: result.rows[0] };
		},
		async authorize(projectId: string, headers: Headers) {
			const key = headers.get("allauth-backend-key") || "";
			if (
				!/^aabk_[a-f0-9-]{36}_[A-Za-z0-9_-]{43}$/.test(key) ||
				headers.has("authorization")
			)
				throw new APIError("UNAUTHORIZED", {
					message: "A scoped backend credential is required.",
				});
			const result = await database.query(
				'SELECT id FROM public."allauthProjectBackendCredential" WHERE "projectId"=$1 AND "keyHash"=$2 AND scope=\'directory:read\' AND "revokedAt" IS NULL AND "expiresAt">NOW()',
				[projectId, hash(key)],
			);
			if (!result.rows[0])
				throw new APIError("UNAUTHORIZED", {
					message: "The backend credential is invalid or expired.",
				});
		},
	};
}

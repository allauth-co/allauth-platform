import { createHmac, randomBytes, randomUUID } from "node:crypto";
import type { PoolClient } from "pg";
import { canonicalIP } from "./control/security-policy";
import { recordOwnedProjectEvent } from "./projects/owned-project-engine-store";

/** Use the installed platform session record and cookie contract across credential handlers. */
export function createPlatformSessionIssuer(options: {
	issuer: string;
	signingSecret: string;
	trustedIP: (request: Request) => string | null;
}) {
	const secure = options.issuer.startsWith("https:");
	const prefix = `${secure ? "__Secure-" : ""}better-auth.`;

	function cookie(name: string, value: string, maxAge?: number) {
		const signature = createHmac("sha256", options.signingSecret)
			.update(value)
			.digest("base64");
		return `${prefix}${name}=${encodeURIComponent(`${value}.${signature}`)}; Path=/; HttpOnly; SameSite=Lax${maxAge === undefined ? "" : `; Max-Age=${maxAge}`}${secure ? "; Secure" : ""}`;
	}

	async function issue(
		client: PoolClient,
		input: {
			userId: string;
			lifetime: number;
			request: Request;
			path: string;
			activeOrganizationId?: string | null;
			activeTeamId?: string | null;
		},
	) {
		const id = randomUUID();
		const token = randomBytes(32).toString("base64url");
		const inserted = await client.query<{ createdAt: Date }>(
			`INSERT INTO public."session" (id,token,"userId","expiresAt","updatedAt","ipAddress","userAgent","activeOrganizationId","activeTeamId")
			 VALUES ($1,$2,$3,now()+$4::integer*interval '1 second',now(),$5,$6,$7,$8) RETURNING "createdAt"`,
			[
				id,
				token,
				input.userId,
				input.lifetime,
				canonicalIP(options.trustedIP(input.request)) ?? "",
				input.request.headers.get("user-agent") ?? "",
				input.activeOrganizationId ?? null,
				input.activeTeamId ?? null,
			],
		);
		await recordOwnedProjectEvent(client, {
			type: "session.created",
			outcome: "success",
			userId: input.userId,
			targetId: id,
			metadata: { path: input.path },
		});
		return { id, token, createdAt: inserted.rows[0]!.createdAt };
	}

	return {
		cookie,
		issue,
		expire: (name: string) =>
			`${prefix}${name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure ? "; Secure" : ""}`,
	};
}

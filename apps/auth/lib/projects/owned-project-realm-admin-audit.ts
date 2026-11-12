import { randomUUID } from "node:crypto";
import type { PoolClient } from "pg";
import type { ControlEventInput } from "../control/types";
import { accountLinkJson } from "./owned-project-account-links";
import type { createProjectEngineStore } from "./owned-project-engine-store";

export type RealmAdminAuditContext = Pick<
	ControlEventInput,
	"ipAddress" | "userAgent"
>;

/** Record the existing administrator envelope from trusted realm authority and bounded request context. */
export async function recordOwnedRealmAdminEvent(
	store: Pick<ReturnType<typeof createProjectEngineStore>, "recordEvent">,
	client: PoolClient,
	path: `/admin/${string}`,
	input: RealmAdminAuditContext &
		Pick<ControlEventInput, "actorId" | "userId" | "targetId"> & {
			errorCode?: string;
		},
) {
	const { errorCode, ...attributes } = input;
	if (!errorCode && attributes.actorId)
		await client.query(
			`INSERT INTO "allauthAudit" (id,"actorId",action,"targetId","createdAt")
			 VALUES ($1,$2,$3,$4,statement_timestamp())`,
			[randomUUID(), attributes.actorId, path, attributes.targetId ?? null],
		);
	await store.recordEvent(client, {
		...attributes,
		type: path.slice(1).replaceAll("/", "."),
		outcome: errorCode ? "failure" : "success",
		metadata: { path, ...(errorCode ? { errorCode } : {}) },
	});
}

/** Apply the realm's pre-handler policy before recording a browser administrator event. */
export function realmAdministratorRequestGuard(current: {
	user: { emailVerified: boolean };
	session: { impersonatedBy?: string | null };
}) {
	if (!current.user.emailVerified)
		return accountLinkJson(
			{ message: "Administrative actions require a verified email address." },
			403,
		);
	if (current.session.impersonatedBy)
		return accountLinkJson(
			{
				message: "Administrative actions are unavailable during impersonation.",
			},
			403,
		);
}

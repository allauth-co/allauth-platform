import { randomUUID } from "node:crypto";
import type { PoolClient } from "pg";
import type { OwnedProjectAccountDeletionOptions } from "./owned-project-account-deletion";
import {
	claimProjectUserDeletion,
	eraseLockedProjectUser,
	lockProjectUserDeletion,
	releaseProjectUserDeletion,
} from "./owned-project-account-deletion";
import type { OwnedProjectEmailAliases } from "./owned-project-email-aliases";
import type { createProjectEngineStore } from "./owned-project-engine-store";

type Store = ReturnType<typeof createProjectEngineStore>;
export type ProjectGuestProof = { token: string } | { userId: string };
type Erasure =
	| { status: "deleted"; userId: string }
	| { status: "missing" | "ineligible" | "pending" | "unavailable" };

/** Read and retire guest records using the same deletion fence as other project accounts. */
export function createOwnedProjectGuest(options: {
	store: Store;
	emailAliases?: Pick<OwnedProjectEmailAliases, "reserved">;
	denyProvisioning(
		client: PoolClient,
		request: Request,
		email: string,
	): Promise<boolean>;
	beforeDelete: OwnedProjectAccountDeletionOptions["beforeDelete"];
	revoke(
		client: PoolClient,
		request: Request,
		userId: string,
		path: string,
	): Promise<void>;
}) {
	const { store } = options;

	async function authority(client: PoolClient, proof: ProjectGuestProof) {
		const byToken = "token" in proof;
		const {
			rows: [observed],
		} = await client.query<{ userId: string; token: string }>(
			`SELECT "userId",token FROM "session" WHERE ${byToken ? "token" : '"userId"'}=$1
			 AND "expiresAt">clock_timestamp() AND "impersonatedBy" IS NULL
			 ORDER BY "createdAt" DESC,id LIMIT 1`,
			[byToken ? proof.token : proof.userId],
		);
		if (!observed) return { status: "missing" } as const;
		const user = await store.lockUser(client, observed.userId);
		if (
			!user ||
			user.banned ||
			user.directoryDisabled ||
			user.directoryManaged ||
			!user.isAnonymous
		)
			return { status: "ineligible" } as const;
		if (!(await store.lockSession(client, observed.token, user.id, false)))
			return { status: "missing" } as const;
		return { status: "guest", user, token: observed.token } as const;
	}

	return {
		async create(client: PoolClient, request: Request) {
			const id = randomUUID();
			const email = `${id}@anonymous.placeholder.invalid`;
			if (await options.denyProvisioning(client, request, email))
				return { status: "blocked" } as const;
			if (options.emailAliases?.reserved(email))
				return { status: "reserved" } as const;
			await client.query(
				`INSERT INTO "user" (id,name,email,role,"emailVerified","isAnonymous")
				 VALUES ($1,'Anonymous',$2,'guest',FALSE,TRUE)`,
				[id, email],
			);
			const user = await store.lockUser(client, id);
			if (!user)
				throw new Error("The project guest account could not be created.");
			return { status: "created", user } as const;
		},
		async erase(
			request: Request,
			proof: ProjectGuestProof,
			path: string,
		): Promise<Erasure> {
			const lease = randomUUID();
			const claim = await store.transaction(async (client) => {
				const current = await authority(client, proof);
				if (current.status !== "guest") return current;
				const key = await claimProjectUserDeletion(
					client,
					current.user.id,
					lease,
				);
				return key ? { ...current, key } : ({ status: "pending" } as const);
			});
			if (claim.status !== "guest") return claim;
			let finished = false;
			try {
				const fence = await options.beforeDelete({ request, user: claim.user });
				if (fence instanceof Response) return { status: "unavailable" };
				const result = await store.transaction(
					async (client): Promise<Erasure> => {
						const current = await authority(client, { token: claim.token });
						if (current.status !== "guest") return current;
						const id = current.user.id;
						if (
							id !== claim.user.id ||
							!(await lockProjectUserDeletion(client, claim.key, lease)) ||
							(fence && !(await fence.verify(client)))
						)
							return { status: "unavailable" };
						await options.revoke(client, request, id, path);
						await eraseLockedProjectUser(client, id, claim.key);
						await store.record(client, "user.deleted", "success", path, id, id);
						return { status: "deleted", userId: id };
					},
				);
				finished = result.status === "deleted";
				return result;
			} catch {
				return { status: "unavailable" };
			} finally {
				if (!finished)
					await store.transaction((client) =>
						releaseProjectUserDeletion(client, claim.key, lease),
					);
			}
		},
	};
}

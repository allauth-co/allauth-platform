import type { AuthContext } from "better-auth";
const guarded = new WeakSet<AuthContext["internalAdapter"]>();
/** Install only after Better Auth has finished rebuilding its final internal adapter. */
export function guardAvatarUserDeletion(
	adapter: AuthContext["internalAdapter"],
	beforeDelete: (userId: string) => Promise<void>,
) {
	if (guarded.has(adapter)) return;
	const remove = adapter.deleteUser.bind(adapter);
	adapter.deleteUser = async (userId) => {
		await beforeDelete(userId);
		return remove(userId);
	};
	guarded.add(adapter);
}

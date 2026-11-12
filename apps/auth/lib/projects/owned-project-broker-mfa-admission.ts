import type { PoolClient } from "pg";
import { admitOwnedProjectNativeRoute } from "./owned-project-native-admission";

export const projectBrokerMfaPath = "/broker-two-factor/verify";

/** Consume the same persisted rate-limit window as the legacy broker MFA route. */
export function admitOwnedProjectBrokerMfa(
	client: PoolClient,
	ip: string | null,
): Promise<Response | null> {
	return admitOwnedProjectNativeRoute(client, ip, projectBrokerMfaPath, {
		max: 100,
		windowMs: 60_000,
	});
}

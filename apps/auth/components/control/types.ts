import type { SecurityPolicy, SecurityRule } from "@/lib/control/security";

export type {
	ControlOutcome,
	ControlEvent,
	ControlOverview,
	ControlEventsResponse,
	ControlSession,
	ControlSessionsResponse,
} from "@/lib/control/types";
export type { SecurityPolicy, SecurityRule };

export type SecurityResponse = {
	policy: SecurityPolicy;
	rules: SecurityRule[];
	stats: {
		blockedRequests: number;
		last24hFailures: number;
		activeRules: number;
	};
	capabilities: {
		credentialStuffing: boolean;
		velocity: boolean;
		blockRules: boolean;
		newDeviceNotifications: boolean;
		botChallenge: boolean;
		impossibleTravel: boolean;
		breachedPasswords: boolean;
	};
};

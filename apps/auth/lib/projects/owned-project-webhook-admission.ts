import { ownedWebhookSelectors as eligibleWebhookSelectors } from "../../scripts/project-engine-webhook-admission.mjs";
import type { AuthPolicy } from "../auth-policy/policy";
import type { webhookEventTypes } from "../control/webhook-contract";

export {
	assertOwnedProjectWebhookAdmission,
	ownedWebhookAccountsSupported,
	ownedWebhookUsesPolicyGuard,
	storedProjectWebhookSelectors,
} from "../../scripts/project-engine-webhook-admission.mjs";

export function ownedWebhookSelectors(
	policy: AuthPolicy,
): readonly (typeof webhookEventTypes)[number][] {
	return eligibleWebhookSelectors(policy);
}

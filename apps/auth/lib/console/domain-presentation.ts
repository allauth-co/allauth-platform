import type { DomainIssue, PublicCustomHostname } from "../domains/types";

export const domainIssueMessage: Record<DomainIssue, string> = {
	"ownership-required":
		"Add the ownership TXT record to prove you control this hostname, then verify again.",
	"infrastructure-required":
		"Domain routing is being prepared. Ownership can be checked now; routing and TLS remain pending.",
	"provider-unavailable":
		"The certificate service could not be reached. Your reservation is retained; verify again later.",
	"quota-exhausted":
		"The service has reached its included hostname capacity. Contact your AllAuth administrator before activation.",
	"provider-conflict":
		"This hostname conflicts with an existing provider registration. Contact your AllAuth administrator.",
	"routing-required":
		"Add the routing CNAME record, then verify again after DNS has propagated.",
	"certificate-pending":
		"The certificate is still being issued. Add any certificate validation records shown below and verify again.",
	"cleanup-pending":
		"Routing has been disabled. Provider cleanup must finish before this hostname can be reused.",
};

/** Ownership, routing, and TLS are independent facts; a pending certificate never becomes an active label. */
export function domainStatusFacts(
	host: Pick<
		PublicCustomHostname,
		"status" | "ownershipVerifiedAt" | "routingVerifiedAt" | "certificateStatus"
	>,
) {
	const removing = host.status === "deleting";
	return {
		ownership: {
			ready: !!host.ownershipVerifiedAt,
			label: host.ownershipVerifiedAt ? "Verified" : "Pending",
		},
		routing: {
			ready: !!host.routingVerifiedAt && !removing,
			label: removing
				? "Disabled"
				: host.routingVerifiedAt
					? "Verified"
					: "Pending",
		},
		tls: {
			ready: host.certificateStatus === "active" && !removing,
			label: removing
				? "Removing"
				: host.certificateStatus === "active"
					? "Active"
					: host.certificateStatus
						? host.certificateStatus.replaceAll("_", " ")
						: "Pending",
		},
	};
}

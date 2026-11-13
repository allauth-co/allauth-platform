"use client";

import { useQuery } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { toast } from "sonner";
import type { AllAuthClient } from "@/sdk/client";
import { authError } from "@/sdk/helpers";

export function useHostedOrganizationPermission(
	client: AllAuthClient,
	userId: string | undefined,
	organizationId: string | undefined,
	resource: "organization" | "ac" | "member" | "invitation" | "team",
	action: "create" | "read" | "update" | "delete" | "cancel",
) {
	return useQuery({
		queryKey: [
			"hosted-organization",
			"permission",
			userId,
			organizationId,
			resource,
			action,
		],
		enabled: Boolean(userId && organizationId),
		queryFn: async () => {
			const result = await client.organization.hasPermission({
				organizationId,
				permissions: { [resource]: [action] },
			});
			if (result.error) throw new Error(result.error.message);
			return result.data?.success === true;
		},
	});
}

/** Keep one mutation in flight per visible organization management form. */
export function useHostedOrganizationAction() {
	const active = useRef(false);
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState("");
	async function run(work: () => Promise<void>, success: string) {
		if (active.current) return;
		active.current = true;
		setBusy(true);
		setError("");
		try {
			await work();
			toast.success(success);
		} catch (cause) {
			setError(authError(cause));
		} finally {
			active.current = false;
			setBusy(false);
		}
	}
	return { busy, error, run };
}

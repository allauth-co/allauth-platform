"use client";

import { Button } from "@/components/better-auth-ui/ui/button";
import { useAuth } from "../../lib/use-auth";

/** Keep failed security lookups distinct from empty account data and offer a retry. */
export function AccountDataError({ message, retry, isFetching = false }: {
	message: string;
	retry: () => unknown;
	isFetching?: boolean;
}) {
	return <div role="alert" className="space-y-3 p-4">
		<p className="text-sm text-destructive">{message}</p>
		<Button type="button" variant="outline" size="sm" disabled={isFetching} onClick={() => void retry()}>
			{isFetching ? "Retrying…" : "Try again"}
		</Button>
	</div>;
}

/** Recover from an expired account session instead of leaving a disabled query loading forever. */
export function AccountSignInRequired() {
	const { Link, basePaths, viewPaths } = useAuth();
	return <p className="p-4 text-sm">
		Your session has ended. <Link href={`${basePaths.auth}/${viewPaths.auth.signIn}`} className="underline underline-offset-4">Sign in again</Link> to manage account security.
	</p>;
}

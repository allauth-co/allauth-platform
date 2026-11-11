import React from "react";
import type { Metadata } from "next";
import Link from "next/link";
export const metadata: Metadata = {
	title: "Sign-in did not finish",
	robots: { index: false, follow: false },
	referrer: "no-referrer",
};
/** Fixed content deliberately ignores provider query strings and callback destinations. */
export default function AuthenticationErrorPage() {
	return (
		<main className="mx-auto max-w-md px-6 py-16">
			<h1 className="text-2xl font-semibold tracking-tight">
				Sign-in did not finish
			</h1>
			<p className="mt-4 text-muted-foreground">
				Your sign-in session may have expired or could not be verified.
			</p>
			<p className="mt-4">
				Close this window, return to the app or website where you started, and
				try signing in again.
			</p>
			<p className="mt-6">
				<Link href="/sign-in" className="underline underline-offset-4">
					Return to sign in
				</Link>
			</p>
		</main>
	);
}

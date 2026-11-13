import Link from "next/link";

export function AuthenticationErrorGuidance({
	retry,
}: {
	retry?: string;
} = {}) {
	const Region = retry ? "section" : "main";
	return (
		<Region className="mx-auto max-w-md px-6 py-16">
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
				<Link
					href={retry ?? "/sign-in"}
					prefetch={retry ? false : undefined}
					className="underline underline-offset-4"
				>
					Return to sign in
				</Link>
			</p>
		</Region>
	);
}

export function HostedProjectUnavailable() {
	return (
		<section className="mx-auto max-w-sm space-y-2 px-6 py-12 text-center" role="status">
			<h1 className="text-lg font-semibold">Sign-in is temporarily unavailable</h1>
			<p className="text-sm text-muted-foreground">Try again in a moment.</p>
		</section>
	);
}

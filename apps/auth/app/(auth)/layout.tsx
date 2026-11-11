import { Suspense } from "react";

export default function AuthenticationLayout({ children }: { children: React.ReactNode }) {
	return <Suspense fallback={<p role="status" className="text-center text-sm text-muted-foreground">Loading authentication…</p>}>{children}</Suspense>;
}

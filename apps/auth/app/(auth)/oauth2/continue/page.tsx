"use client";
import { useEffect, useState, useRef } from "react";
import { useSearchParams } from "next/navigation";
import { completeAuthentication, errorMessage } from "@/lib/shared";
export default function Page() {
	const params = useSearchParams();
	const [error, setError] = useState("");
	const started = useRef(false);
	useEffect(() => {
		if (started.current) return;
		started.current = true;
		void completeAuthentication(params).catch((e) => setError(errorMessage(e)));
	}, [params]);
	return (
		<div className="max-w-md mx-auto py-16 text-center">
			<h1 className="text-xl font-semibold">
				{error ? "Unable to continue" : "Completing sign in…"}
			</h1>
			{error && (
				<p role="alert" className="text-sm text-destructive mt-4">
					{error}
				</p>
			)}
		</div>
	);
}

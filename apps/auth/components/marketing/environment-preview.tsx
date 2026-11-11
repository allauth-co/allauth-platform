"use client";

import { ArrowUpRight, Layers, ShieldCheck, Terminal } from "lucide-react";
import { useState } from "react";

/** A local-only explanation of independent application environments. */
export function EnvironmentPreview() {
	const [environment, setEnvironment] = useState<"development" | "production">("development");
	const production = environment === "production";
	return (
		<div className="homepage-environments">
			<div className="homepage-environments-heading"><Layers size={19} aria-hidden="true" /> Independent environments</div>
			<div className="homepage-environment-options" role="group" aria-label="Explore environments">
				{(["development", "production"] as const).map((value) => (
					<button type="button" key={value} onClick={() => setEnvironment(value)} aria-pressed={environment === value} className="homepage-environment-option">
						<span className={`homepage-environment-dot homepage-environment-dot-${value}`} />
						<span><strong>{value === "production" ? "Production" : "Development"}</strong><span>Separate identities, users and settings</span></span>
						<ArrowUpRight size={18} aria-hidden="true" />
					</button>
				))}
			</div>
			<div className="homepage-environment-note" aria-live="polite" aria-atomic="true">
				{production ? <ShieldCheck size={18} aria-hidden="true" /> : <Terminal size={18} aria-hidden="true" />}
				<p>{production ? "Users, authentication settings and credentials in Development stay separate from Production." : "Test your integration with its own users and credentials, separate from your live application."}</p>
			</div>
		</div>
	);
}

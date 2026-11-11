"use client";

import { ArrowRight, ArrowUpRight, Check, Code2 } from "lucide-react";
import Link from "next/link";
import { managementHref } from "@/components/control/helpers";
import { Button } from "@/components/ui/button";
import { Badge, CopyValue, DetailPanel } from "./common";
import type { ConsoleProject } from "./shell";

export interface CreatedApplication {
	project: ConsoleProject;
	proxySecret: string;
}

/** Show a newly issued integration key once, after persisted application creation. */
export function ApplicationConnectionPanel({
	secret,
	onClose,
}: {
	secret: CreatedApplication;
	onClose: () => void;
}) {
	return (
		<DetailPanel title="Connect your application" onClose={() => onClose()}>
			<Badge
				tone={secret.project.environment === "production" ? "success" : "blue"}
			>
				{secret.project.environment === "production"
					? "Production"
					: "Development"}
			</Badge>
			<p className="console-panel-intro mt-5">
				Save this integration key in your application’s server environment. It
				is shown once. Keep it out of browser code.
			</p>
			<div className="console-integration-code">
				<div>
					<strong>Server environment</strong>
					<CopyValue
						label="Copy server configuration"
						value={`ALLAUTH_PROJECT=${secret.project.slug}\nALLAUTH_PROXY_SECRET=${secret.proxySecret}\nAPP_ORIGIN=${secret.project.primaryOrigin}`}
					/>
				</div>
				<pre>{`ALLAUTH_PROJECT=${secret.project.slug}\nALLAUTH_PROXY_SECRET=${secret.proxySecret}\nAPP_ORIGIN=${secret.project.primaryOrigin}`}</pre>
			</div>
			<ol className="console-setup-checklist">
				<li>
					<Code2 size={16} />
					<span>
						<strong>Connect the SDK</strong>
						<small>
							Mount the server proxy at /api/allauth, then add AllAuthProvider
							and the sign-in components to your app.
						</small>
					</span>
				</li>
				<li>
					<Check size={16} />
					<span>
						<strong>Test a real sign-in</strong>
						<small>
							Use your app’s configured origin and confirm the user appears in
							this environment.
						</small>
					</span>
				</li>
				<li>
					<ArrowUpRight size={16} />
					<span>
						<strong>
							{secret.project.environment === "production"
								? "Verify production routing"
								: "Create production when ready"}
						</strong>
						<small>
							{secret.project.environment === "production"
								? "Configure your account and frontend API domains, then verify ownership, routing, and TLS."
								: "Keep production users and keys separate. Register your production app’s HTTPS origin."}
						</small>
					</span>
				</li>
			</ol>
			<div className="flex flex-wrap gap-2">
				<Button asChild variant="outline">
					<Link
						href={managementHref(
							"/admin/setup-guide",
							secret.project.slug,
							secret.project.workspaceId,
						)}
						target="_blank"
						rel="noopener noreferrer"
					>
						Integration guide
						<ArrowUpRight size={14} className="ml-2" />
					</Link>
				</Button>
				<Button asChild className="console-primary">
					<Link
						href={managementHref(
							"/admin/overview",
							secret.project.slug,
							secret.project.workspaceId,
						)}
						onClick={onClose}
					>
						Open application
						<ArrowRight size={14} className="ml-2" />
					</Link>
				</Button>
				<Button type="button" variant="outline" onClick={() => onClose()}>
					I’ve saved the key
				</Button>
			</div>
		</DetailPanel>
	);
}

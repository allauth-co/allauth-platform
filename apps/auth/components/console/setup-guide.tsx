"use client";

import { useQuery } from "@tanstack/react-query";
import {
	ArrowRight,
	BookOpen,
	Check,
	Code2,
	Globe,
	KeyRound,
	Package,
} from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";
import { useEffect, useState } from "react";
import { managementHref } from "@/components/control/helpers";
import { Button } from "@/components/ui/button";
import { publishedSdkInstallPeers, publishedSdkVersion } from "@/lib/published-sdk";
import {
	Badge,
	CopyValue,
	managementRequest,
	PageHeading,
	StateMessage,
} from "./common";
import type { ConsoleProject } from "./shell";
import {
	canManageWorkspace,
	useConsoleWorkspaces,
	workspaceProjectQueryKey,
	workspaceProjectsPath,
} from "./workspace-client";
import "./domains.css";

export function ConsoleSetupGuide({
	project,
	workspace,
}: {
	project?: string;
	workspace?: string;
}) {
	const [downloadOrigin, setDownloadOrigin] = useState("https://allauth.co");
	useEffect(() => setDownloadOrigin(window.location.origin), []);
	const archiveName = `allauth-react-${publishedSdkVersion}.tgz`;
	const downloadPath = `/sdk/${archiveName}`;
	const workspaces = useConsoleWorkspaces();
	const selectedWorkspace = workspaces.data?.workspaces.find(
		(item) => item.id === workspace,
	);
	const readable =
		!!workspaces.data &&
		(workspace !== undefined
			? canManageWorkspace(selectedWorkspace)
			: workspaces.data.platformAdmin ||
				workspaces.data.workspaces.some(canManageWorkspace));
	const query = useQuery({
		queryKey: workspaceProjectQueryKey(workspace),
		queryFn: () =>
			managementRequest<{ projects: ConsoleProject[] }>(
				workspaceProjectsPath(workspace),
			),
		enabled: !!project && readable,
	});
	const selected = query.data?.projects.find((item) => item.slug === project);
	const scope = selected?.workspaceId || workspace;
	if (!project)
		return (
			<>
				<PageHeading
					title="Integration guide"
					description="Connect your application to AllAuth with its own environment and server integration key."
				/>
				<div className="console-onboarding-empty">
					<BookOpen size={25} />
					<h2>Choose an application to continue</h2>
					<p>
						The guide uses your environment’s actual identifier and app origin.
						Create a development application first, then connect the SDK and
						test sign-in.
					</p>
					<Button asChild className="console-primary">
						<Link
							href={managementHref("/admin/projects", undefined, workspace)}
						>
							View applications
							<ArrowRight size={14} className="ml-2" />
						</Link>
					</Button>
				</div>
			</>
		);
	const denied = !!workspaces.data && !readable;
	return (
		<>
			<PageHeading
				title="Integration guide"
				description="Connect this environment to a Next.js app, then test a real account before going to production."
			>
				{selected && (
					<>
						<Badge
							tone={selected.environment === "production" ? "success" : "blue"}
						>
							{selected.environment === "production"
								? "Production"
								: "Development"}
						</Badge>
						<Button asChild variant="outline">
							<Link
								href={managementHref("/admin/domains", selected.slug, scope)}
							>
								<Globe size={14} className="mr-2" />
								Domains
							</Link>
						</Button>
					</>
				)}
			</PageHeading>
			<StateMessage
				loading={
					!workspaces.error &&
					!denied &&
					(workspaces.isPending || query.isPending)
				}
				error={
					workspaces.error ||
					query.error ||
					(denied
						? new Error("A workspace owner or admin must connect applications.")
						: query.data && !selected
							? new Error(
									"This application is unavailable in the selected workspace.",
								)
							: undefined)
				}
			/>
			{selected && (
				<div className="console-guide-layout">
					<aside className="console-guide-contents">
						<strong>{selected.name}</strong>
						<span>{selected.primaryOrigin}</span>
						<nav aria-label="Integration steps">
							{[
								["sdk", "1. Get the SDK"],
								["keys", "2. Server environment"],
								["proxy", "3. Add the server proxy"],
								["provider", "4. Add the provider"],
								["components", "5. Add account pages"],
								["social", "6. Connect social sign-in"],
								["test", "7. Test and launch"],
								["support", "8. Optional support access"],
							].map(([id, label]) => (
								<a href={`#${id}`} key={id}>
									{label}
								</a>
							))}
						</nav>
					</aside>
					<div className="console-guide-sections">
						<GuideStep
							id="sdk"
							number={1}
							title="Get the SDK"
							icon={<Package size={18} />}
						>
							<p>
								Install <code>@allauth/react</code> directly from this AllAuth
								service, or download the TypeScript package for local
								installation.
							</p>
							<div className="guide-sdk-download">
								<Badge>Direct download · {publishedSdkVersion}</Badge>
								<Button asChild variant="outline" size="sm">
									<a
										href={downloadPath}
										download={archiveName}
									>
										Download SDK
										<Package size={14} className="ml-2" />
									</a>
								</Button>
							</div>
							<CodeBlock
								label="Install in your application"
								value={["pnpm add", downloadOrigin + downloadPath, ...publishedSdkInstallPeers].join(" ")}
							/>
							<p className="guide-note">
								Direct download, not published to npm. The package exports
								TypeScript source; enable Next.js transpilation below.
							</p>
							<details className="guide-source-alternative">
								<summary>Package from source instead</summary>
								<CodeBlock
									label="Package from the AllAuth repository"
									value={`git clone --branch v${publishedSdkVersion} --depth 1 https://github.com/allauth-co/allauth-sdk.git\ncd allauth-sdk\npnpm --dir packages/react pack`}
								/>
								<CodeBlock
									label="Install your local tarball"
									value={["pnpm add", `/path/to/${archiveName}`, ...publishedSdkInstallPeers].join(" ")}
								/>
							</details>
							<CodeBlock
								label="next.config.ts"
								value={`import type { NextConfig } from "next";\n\nconst nextConfig: NextConfig = {\n  transpilePackages: ["@allauth/react"],\n};\n\nexport default nextConfig;`}
							/>
						</GuideStep>
						<GuideStep
							id="keys"
							number={2}
							title="Set your server environment"
							icon={<KeyRound size={18} />}
						>
							<p>
								Use the integration key shown when this environment was created.
								Keep it in the app server’s environment and out of browser code
								and <code>NEXT_PUBLIC_*</code> variables.
							</p>
							<CodeBlock
								label="Server environment variables"
								value={`ALLAUTH_PROJECT=${selected.slug}\nALLAUTH_PROXY_SECRET=<your saved one-time integration key>\nAPP_ORIGIN=${selected.primaryOrigin}`}
							/>
							<p className="guide-note">
								If the key is lost, rotate this environment’s integration key on
								the Applications screen and update the app’s server
								configuration.
							</p>
						</GuideStep>
						<GuideStep
							id="proxy"
							number={3}
							title="Add the server proxy"
							icon={<Code2 size={18} />}
						>
							<p>
								Create this route in your app. It signs requests on the server
								and keeps session cookies on your app’s domain.
							</p>
							<CodeBlock
								label="app/api/allauth/[...all]/route.ts"
								value={`import { createAllAuthProxy } from "@allauth/react/next";\n\nexport const runtime = "nodejs";\nexport const dynamic = "force-dynamic";\n\nconst proxy = createAllAuthProxy({\n  project: process.env.ALLAUTH_PROJECT!,\n  proxySecret: process.env.ALLAUTH_PROXY_SECRET!,\n  appOrigin: process.env.APP_ORIGIN!,\n  allauthURL: "https://allauth.co",\n});\n\nexport const GET = proxy;\nexport const POST = proxy;`}
							/>
						</GuideStep>
						<GuideStep
							id="provider"
							number={4}
							title="Add the client provider"
							icon={<Code2 size={18} />}
						>
							<p>
								Wrap the app’s account components in one provider. Import the
								SDK stylesheet from your root layout.
							</p>
							<CodeBlock
								label="components/auth-provider.tsx"
								value={`"use client";\n\nimport type { ReactNode } from "react";\nimport { AllAuthProvider } from "@allauth/react";\n\nexport function AuthProvider({ children }: { children: ReactNode }) {\n  return (\n    <AllAuthProvider afterSignInUrl="/" profileUrl="/account">\n      {children}\n    </AllAuthProvider>\n  );\n}`}
							/>
							<CodeBlock
								label="app/layout.tsx"
								value={`import "@allauth/react/styles.css";\nimport type { ReactNode } from "react";\nimport { AuthProvider } from "@/components/auth-provider";\n\nexport default function Layout({ children }: { children: ReactNode }) {\n  return (\n    <html lang="en">\n      <body><AuthProvider>{children}</AuthProvider></body>\n    </html>\n  );\n}`}
							/>
						</GuideStep>
						<GuideStep
							id="components"
							number={5}
							title="Add sign-in and account pages"
							icon={<Code2 size={18} />}
						>
							<p>
								Use the native account components for the flows enabled in this
								environment. Create matching routes for sign-up, password
								recovery, and account management.
							</p>
							<CodeBlock
								label="app/sign-in/page.tsx"
								value={`"use client";\nimport { SignIn } from "@allauth/react";\n\nexport default function Page() {\n  return <SignIn forgotPasswordUrl="/forgot-password" />;\n}`}
							/>
							<CodeBlock
								label="app/account/page.tsx"
								value={`"use client";\nimport { UserProfile } from "@allauth/react";\n\nexport default function Page() {\n  return <UserProfile />;\n}`}
							/>
							<div className="guide-component-table">
								<table>
									<thead>
										<tr>
											<th>Route or placement</th>
											<th>Component</th>
										</tr>
									</thead>
									<tbody>
										<tr>
											<td>/sign-up</td>
											<td>
												<code>SignUp</code>
											</td>
										</tr>
										<tr>
											<td>/forgot-password</td>
											<td>
												<code>ForgotPassword</code>
											</td>
										</tr>
										<tr>
											<td>/reset-password</td>
											<td>
												<code>ResetPassword</code>
											</td>
										</tr>
										<tr>
											<td>App header</td>
											<td>
												<code>UserButton</code>,{" "}
												<code>OrganizationSwitcher</code>
											</td>
										</tr>
									</tbody>
								</table>
							</div>
							<p className="guide-note">
								Account settings include profile, password, passkeys,
								authenticator MFA, recovery codes, and sessions. Organization
								actions follow real membership and role permissions.
							</p>
						</GuideStep>
						<GuideStep
							id="social"
							number={6}
							title="Connect Google, Apple and Microsoft"
							icon={<KeyRound size={18} />}
						>
							<p>
								Google, Apple and Microsoft are included in the standard
								sign-in and sign-up components. Each button appears when its
								connection is configured for this environment.
							</p>
							<p>
								Connect Google under User &amp; authentication → Social
								connections. Your operator connects Apple with an Apple
								Services ID and Microsoft with a Microsoft Entra app registration.
								Register the exact return URLs below with each provider.
							</p>
							<CodeBlock label="Google return URL" value={`${selected.primaryOrigin}/api/allauth/callback/google`} />
							{selected.primaryOrigin.startsWith("https:") ? (
								<CodeBlock label="Apple return URL" value={`${selected.primaryOrigin}/api/allauth/callback/apple`} />
							) : (
								<p className="guide-note">Apple requires an HTTPS app origin. Use a separate environment with an HTTPS origin to test Apple sign-in.</p>
							)}
							<CodeBlock label="Microsoft return URL" value={`${selected.primaryOrigin}/api/allauth/callback/microsoft`} />
							<p className="guide-note">
								Use separate Development and Production connections. Install this
								SDK in existing apps to receive the provider buttons automatically,
								then test each enabled provider through sign-in, sign-up and sign-out.
							</p>
						</GuideStep>
						<GuideStep
							id="test"
							number={7}
							title="Test sign-in, then launch"
							icon={<Check size={18} />}
						>
							<ul className="guide-test-list">
								<li>
									Start the app at <strong>{selected.primaryOrigin}</strong> and
									open its sign-in page.
								</li>
								<li>
									Create or sign in with a test account and confirm it appears
									in this environment’s Users screen.
								</li>
								<li>
									Test sign-out, recovery, and the MFA or passkey flows you
									enable.
								</li>
								<li>
									Create the separate production environment with your app’s
									HTTPS origin. Use its own integration key in the production
									server.
								</li>
								<li>
									For custom hostnames, add the DNS records and verify
									ownership, routing, and TLS on the Domains screen.
								</li>
							</ul>
							<div className="flex flex-wrap gap-2">
								<Button asChild className="console-primary">
									<Link
										href={managementHref("/admin/users", selected.slug, scope)}
									>
										Open users
										<ArrowRight size={14} className="ml-2" />
									</Link>
								</Button>
								<Button asChild variant="outline">
									<Link
										href={managementHref(
											"/admin/configure",
											selected.slug,
											scope,
										)}
									>
										Configure authentication
									</Link>
								</Button>
								<Button asChild variant="outline">
									<Link
										href={managementHref("/admin/projects", undefined, scope)}
									>
										Applications
									</Link>
								</Button>
							</div>
						</GuideStep>
						<GuideStep id="support" number={8} title="Enable connected-app support" icon={<Code2 size={18} />}>
							<p>Add <code>supportAccess: {"{ enabled: true }"}</code> to the server proxy options and <code>supportAccess</code> to the shared <code>AllAuthProvider</code> or <code>AllAuthUIProvider</code>. Keep the provider mounted across your app so the support banner and end action stay visible.</p>
							<CodeBlock label="Support callback URL" value={`${selected.primaryOrigin}/api/allauth/support/callback`} />
							<p>Register this exact URL under User &amp; authentication → Support access, then enable it. If your proxy uses a different mount, set the same <code>basePath</code> in its support options and provider, and update the callback path.</p>
							<p className="guide-note">For local support testing, use different hostnames for the app and AllAuth, such as localhost and 127.0.0.1. Different ports on one hostname share cookies.</p>
							<p>Start impersonation from Users and select Open connected app. Test the target banner, account restrictions and End support session using a test account. Ending support restores a still-valid prior app sign-in; support access keeps its original 15-minute expiry.</p>
						</GuideStep>
					</div>
				</div>
			)}
		</>
	);
}

function GuideStep({
	id,
	number,
	title,
	icon,
	children,
}: {
	id: string;
	number: number;
	title: string;
	icon: ReactNode;
	children: ReactNode;
}) {
	return (
		<section id={id} className="console-card guide-step">
			<div className="console-card-heading">
				<div>
					<span className="guide-step-number">{number}</span>
					<h2>{title}</h2>
				</div>
				{icon}
			</div>
			<div className="console-card-body">{children}</div>
		</section>
	);
}
function CodeBlock({ label, value }: { label: string; value: string }) {
	return (
		<div className="guide-code">
			<div>
				<strong>{label}</strong>
				<CopyValue label={`Copy ${label}`} value={value} />
			</div>
			<pre>{value}</pre>
		</div>
	);
}

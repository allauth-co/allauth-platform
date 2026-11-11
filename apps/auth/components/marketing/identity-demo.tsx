"use client";

import { AppSelect, AppSelectOption } from "@/components/ui/app-select";

import { Google } from "@better-auth-ui/react";
import {
	ArrowRight,
	CodeXml,
	Fingerprint,
	KeyRound,
	Mail,
	Pause,
	Play,
	ShieldCheck,
	Users,
	UsersRound,
} from "lucide-react";
import { useId, useState } from "react";
import { LogoIcon } from "@/components/logo";
import "./identity-demo.css";

type DemoFeature =
	| "app"
	| "allauth"
	| "passkeys"
	| "google"
	| "email"
	| "users"
	| "organizations"
	| "roles";
type DemoEnvironment = "development" | "production";

const projects = ["Example app", "Customer portal", "Team dashboard"] as const;

const featureDetails: Record<
	DemoFeature,
	{ title: string; description: string; path: "signin" | "access" | "all" }
> = {
	app: {
		title: "Your product. Your sign-in experience.",
		description:
			"Connect your website, mobile app or API to one place for authentication.",
		path: "signin",
	},
	allauth: {
		title: "One home for identity.",
		description:
			"Manage sign-in methods, users and access from the same console.",
		path: "all",
	},
	passkeys: {
		title: "A simpler way to sign in.",
		description:
			"Let people use a fingerprint, face or device PIN instead of remembering a password.",
		path: "signin",
	},
	google: {
		title: "A familiar first step.",
		description:
			"Let people sign in with their Google account and return to your app.",
		path: "signin",
	},
	email: {
		title: "An everyday sign-in option.",
		description:
			"Give people an email-based way to create an account and sign in.",
		path: "signin",
	},
	users: {
		title: "Know who has access.",
		description:
			"Bring accounts and sign-in methods together in a single user directory.",
		path: "access",
	},
	organizations: {
		title: "Built around your customers’ teams.",
		description:
			"Group users into organizations and manage their memberships in one place.",
		path: "access",
	},
	roles: {
		title: "The right access for each person.",
		description:
			"Use roles to organize what members can do within an organization.",
		path: "access",
	},
};

/** Interactive, illustrative identity flow for the public AllAuth homepage. */
export function IdentityDemo() {
	const projectId = useId();
	const detailId = useId();
	const [project, setProject] = useState<string>(projects[0]);
	const [environment, setEnvironment] =
		useState<DemoEnvironment>("development");
	const [feature, setFeature] = useState<DemoFeature>("passkeys");
	const [paused, setPaused] = useState(false);
	const details = featureDetails[feature];

	function selectFeature(nextFeature: DemoFeature) {
		setFeature(nextFeature);
	}

	return (
		<div
			className="identity-demo"
			data-path={details.path}
			data-paused={paused}
			data-environment={environment}
			role="group"
			aria-label="Explore a sample AllAuth identity flow"
		>
			<div className="identity-demo-topline">
				<span className="identity-demo-preview">
					<span aria-hidden="true" />
					Interactive preview
				</span>
				<button
					type="button"
					className="identity-demo-motion"
					onClick={() => setPaused((current) => !current)}
					aria-pressed={paused}
					aria-label={paused ? "Resume animation" : "Pause animation"}
				>
					{paused ? <Play size={12} /> : <Pause size={12} />}
					<span>{paused ? "Play" : "Pause"}</span>
				</button>
			</div>

			<div className="identity-demo-flow">
				<div
					className="identity-demo-connection identity-demo-connection-in"
					aria-hidden="true"
				>
					<span />
					<span />
				</div>
				<div
					className="identity-demo-connection identity-demo-connection-out"
					aria-hidden="true"
				>
					<span />
					<span />
				</div>
				<button
					type="button"
					className="identity-demo-node identity-demo-app"
					aria-pressed={feature === "app"}
					aria-controls={detailId}
					onClick={() => selectFeature("app")}
				>
					<CodeXml size={26} aria-hidden="true" />
					<strong>Your app</strong>
					<span>WEB · MOBILE · API</span>
				</button>
				<button
					type="button"
					className="identity-demo-brand"
					aria-pressed={feature === "allauth"}
					aria-controls={detailId}
					onClick={() => selectFeature("allauth")}
				>
					<span className="identity-demo-brand-mark">
						<LogoIcon aria-hidden="true" />
					</span>
					<strong>AllAuth</strong>
				</button>
				<button
					type="button"
					className="identity-demo-node identity-demo-users"
					aria-pressed={feature === "users"}
					aria-controls={detailId}
					onClick={() => selectFeature("users")}
				>
					<UsersRound size={26} aria-hidden="true" />
					<strong>Your users</strong>
					<span>ACCOUNTS · TEAMS · ACCESS</span>
				</button>
			</div>

			<div className="identity-demo-stem" aria-hidden="true">
				<span />
			</div>

			<div className="identity-demo-console">
				<div className="identity-demo-console-heading">
					<span className="identity-demo-window-dots" aria-hidden="true">
						<i />
						<i />
						<i />
					</span>
					<span>Identity console</span>
					<span className="identity-demo-sample">Sample project</span>
				</div>
				<div className="identity-demo-project-row">
					<div className="identity-demo-project">
						<label htmlFor={projectId}>Project</label>
						<div className="identity-demo-select">
							<AppSelect
								id={projectId}
								value={project}
								onValueChange={(selection) => setProject(selection)}
							>
								{projects.map((name) => (
									<AppSelectOption key={name} value={name}>
										{name}
									</AppSelectOption>
								))}
							</AppSelect>
						</div>
					</div>
					<div
						className="identity-demo-environments"
						role="group"
						aria-label="Sample project environment"
					>
						{(["development", "production"] as const).map((stage) => (
							<button
								key={stage}
								type="button"
								aria-pressed={environment === stage}
								aria-controls={detailId}
								onClick={() => setEnvironment(stage)}
							>
								{stage === "development" ? "Development" : "Production"}
							</button>
						))}
					</div>
				</div>

				<div className="identity-demo-config-row">
					<span className="identity-demo-row-label">Sign-in methods</span>
					<div
						className="identity-demo-options"
						role="group"
						aria-label="Explore sign-in methods"
					>
						<button
							type="button"
							aria-pressed={feature === "passkeys"}
							aria-controls={detailId}
							onClick={() => selectFeature("passkeys")}
						>
							<KeyRound size={14} aria-hidden="true" />
							Passkeys
						</button>
						<button
							type="button"
							aria-pressed={feature === "google"}
							aria-controls={detailId}
							onClick={() => selectFeature("google")}
						>
							<Google width={14} height={14} aria-hidden="true" />
							Google
						</button>
						<button
							type="button"
							aria-pressed={feature === "email"}
							aria-controls={detailId}
							onClick={() => selectFeature("email")}
						>
							<Mail size={14} aria-hidden="true" />
							Email
						</button>
					</div>
					<ArrowRight
						size={13}
						className="identity-demo-row-arrow"
						aria-hidden="true"
					/>
				</div>
				<div className="identity-demo-config-row">
					<span className="identity-demo-row-label">Access</span>
					<div
						className="identity-demo-options"
						role="group"
						aria-label="Explore access management"
					>
						<button
							type="button"
							aria-pressed={feature === "users"}
							aria-controls={detailId}
							onClick={() => selectFeature("users")}
						>
							<Users size={14} aria-hidden="true" />
							Users
						</button>
						<button
							type="button"
							aria-pressed={feature === "organizations"}
							aria-controls={detailId}
							onClick={() => selectFeature("organizations")}
						>
							<UsersRound size={14} aria-hidden="true" />
							Organizations
						</button>
						<button
							type="button"
							aria-pressed={feature === "roles"}
							aria-controls={detailId}
							onClick={() => selectFeature("roles")}
						>
							<ShieldCheck size={14} aria-hidden="true" />
							Roles
						</button>
					</div>
					<ArrowRight
						size={13}
						className="identity-demo-row-arrow"
						aria-hidden="true"
					/>
				</div>
				<div
					className="identity-demo-detail"
					id={detailId}
					role="status"
					aria-live="polite"
					aria-atomic="true"
				>
					<span className="identity-demo-detail-icon" aria-hidden="true">
						{details.path === "access" ? (
							<ShieldCheck size={20} />
						) : (
							<Fingerprint size={20} />
						)}
					</span>
					<div>
						<div className="identity-demo-detail-context">
							{project} <span aria-hidden="true">/</span>{" "}
							{environment === "development"
								? "Independent development"
								: "Independent production"}
						</div>
						<strong>{details.title}</strong>
						<p>{details.description}</p>
					</div>
				</div>
			</div>
			<p className="identity-demo-caption">
				Click around. See how it fits together.
			</p>
		</div>
	);
}

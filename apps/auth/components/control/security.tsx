"use client";

import { AppSelect, AppSelectOption } from "@/components/ui/app-select";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, RefreshCw, ShieldCheck, ShieldOff } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import {
	Card,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle,
} from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import {
	Dialog,
	DialogContent,
	DialogDescription,
	DialogFooter,
	DialogHeader,
	DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
	Table,
	TableBody,
	TableCell,
	TableHead,
	TableHeader,
	TableRow,
} from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { errorMessage } from "@/lib/shared";
import { createControlRequest } from "./api";
import { ControlError, ControlLoading } from "./common";
import {
	controlQueryScope,
	dateToISO,
	formatDateTime,
	parseEmailDomains,
} from "./helpers";
import type { SecurityPolicy, SecurityResponse, SecurityRule } from "./types";

const numericFields = [
	{
		key: "maxFailuresPerIp",
		label: "Failed attempts per IP",
		description: "Block after this many failed authentication attempts.",
		min: 3,
		max: 1000,
	},
	{
		key: "failureWindowSeconds",
		label: "Failure window (seconds)",
		description:
			"Count failures within this period. 900 seconds is 15 minutes.",
		min: 60,
		max: 86400,
	},
	{
		key: "blockSeconds",
		label: "Automatic block duration (seconds)",
		description:
			"How long a rate-limit block lasts. 900 seconds is 15 minutes.",
		min: 60,
		max: 86400,
	},
	{
		key: "maxSignUpsPerIp",
		label: "Registrations per IP",
		description: "Allow this many account registrations in each window.",
		min: 1,
		max: 1000,
	},
	{
		key: "signUpWindowSeconds",
		label: "Registration window (seconds)",
		description: "3600 seconds is one hour.",
		min: 60,
		max: 86400,
	},
	{
		key: "logRetentionDays",
		label: "Audit retention (days)",
		description:
			"Older recorded events are removed under this retention policy.",
		min: 7,
		max: 365,
	},
] as const;

function PolicyEditor({
	policy,
	notificationsAvailable,
	project,
}: {
	policy: SecurityPolicy;
	notificationsAvailable: boolean;
	project?: string;
}) {
	const controlRequest = createControlRequest(project);
	const queryClient = useQueryClient();
	const [draft, setDraft] = useState<SecurityPolicy>(policy);
	const [domains, setDomains] = useState(policy.blockedEmailDomains.join("\n"));
	const [busy, setBusy] = useState(false);
	async function save() {
		setBusy(true);
		try {
			const next = {
				...draft,
				blockedEmailDomains: parseEmailDomains(domains),
			};
			const response = await controlRequest<{ policy: SecurityPolicy }>(
				"security/update",
				{ method: "POST", body: JSON.stringify({ policy: next }) },
			);
			setDraft(response.policy);
			setDomains(response.policy.blockedEmailDomains.join("\n"));
			toast.success("Security policy saved");
			await queryClient.invalidateQueries({
				queryKey: controlQueryScope(project),
			});
		} catch (error) {
			toast.error(errorMessage(error));
		} finally {
			setBusy(false);
		}
	}
	return (
		<Card>
			<CardHeader>
				<CardTitle className="text-base">Security policy</CardTitle>
				<CardDescription>
					Control authentication limits, domain restrictions and activity
					retention.
				</CardDescription>
			</CardHeader>
			<CardContent>
				<form
					className="space-y-6"
					onSubmit={(event) => {
						event.preventDefault();
						void save();
					}}
				>
					<fieldset className="space-y-3" disabled={busy}>
						<legend className="text-sm font-medium mb-3">
							Protection mode
						</legend>
						<div className="grid sm:grid-cols-2 gap-3">
							{(
								[
									[
										"enforce",
										"Enforce",
										"Block matching rules and requests that exceed limits.",
									],
									[
										"monitor",
										"Monitor",
										"Record matches without blocking requests, including explicit rules.",
									],
								] as const
							).map(([mode, title, description]) => (
								<label
									key={mode}
									className={`flex gap-3 rounded-lg border p-4 cursor-pointer ${draft.mode === mode ? "border-primary bg-primary/5" : ""}`}
								>
									<input
										type="radio"
										name="security-mode"
										value={mode}
										checked={draft.mode === mode}
										onChange={() => setDraft({ ...draft, mode })}
										className="mt-1"
									/>
									<span>
										<span className="font-medium text-sm">{title}</span>
										<span className="block text-xs text-muted-foreground mt-1">
											{description}
										</span>
									</span>
								</label>
							))}
						</div>
						<p className="text-xs text-muted-foreground">
							Limits continue to count in monitor mode. Switching to enforcement
							uses the current counts.
						</p>
					</fieldset>
					<fieldset
						disabled={busy}
						className="grid sm:grid-cols-2 lg:grid-cols-3 gap-5"
					>
						{numericFields.map(({ key, label, description, min, max }) => (
							<div key={key} className="space-y-2">
								<Label htmlFor={`policy-${key}`}>{label}</Label>
								<Input
									id={`policy-${key}`}
									type="number"
									required
									min={min}
									max={max}
									step={1}
									value={draft[key]}
									onChange={(event) =>
										setDraft({ ...draft, [key]: Number(event.target.value) })
									}
									aria-describedby={`policy-${key}-help`}
								/>
								<p
									id={`policy-${key}-help`}
									className="text-xs text-muted-foreground"
								>
									{description}
								</p>
							</div>
						))}
					</fieldset>
					<div className="space-y-2">
						<Label htmlFor="policy-domains">Blocked email domains</Label>
						<Textarea
							id="policy-domains"
							value={domains}
							onChange={(event) => setDomains(event.target.value)}
							disabled={busy}
							rows={4}
							placeholder="example.com"
							aria-describedby="policy-domains-help"
						/>
						<p
							id="policy-domains-help"
							className="text-xs text-muted-foreground"
						>
							One domain per line, up to 200. Matches are exact; add subdomains
							separately. These entries have no expiry. Use a block rule below
							for a reason and optional expiry.
						</p>
					</div>
					<div className="flex gap-3 items-start">
						<Checkbox
							id="policy-device-notifications"
							checked={draft.newDeviceNotifications}
							disabled={busy || !notificationsAvailable}
							onCheckedChange={(checked) =>
								setDraft({ ...draft, newDeviceNotifications: checked === true })
							}
						/>
						<div>
							<Label htmlFor="policy-device-notifications">
								Email users about new devices
							</Label>
							<p className="text-xs text-muted-foreground mt-1">
								{notificationsAvailable
									? "Send a security email after a verified sign-in from a device not previously recognized."
									: "Not active: email notifications are not configured for this deployment."}
							</p>
						</div>
					</div>
					<div className="flex flex-wrap gap-3 items-center">
						<Button type="submit" disabled={busy}>
							{busy ? "Saving…" : "Save policy"}
						</Button>
						<Button
							type="button"
							variant="ghost"
							disabled={busy}
							onClick={() => {
								setDraft(policy);
								setDomains(policy.blockedEmailDomains.join("\n"));
							}}
						>
							Reset changes
						</Button>
					</div>
				</form>
			</CardContent>
		</Card>
	);
}

function BlockRules({
	rules,
	available,
	project,
}: {
	rules: SecurityRule[];
	available: boolean;
	project?: string;
}) {
	const controlRequest = createControlRequest(project);
	const queryClient = useQueryClient();
	const [type, setType] = useState<SecurityRule["type"]>("ip");
	const [value, setValue] = useState("");
	const [reason, setReason] = useState("");
	const [expiry, setExpiry] = useState("");
	const [busy, setBusy] = useState(false);
	const [selected, setSelected] = useState<SecurityRule | null>(null);
	async function add() {
		setBusy(true);
		try {
			const expiresAt = dateToISO(expiry);
			if (
				expiresAt &&
				(new Date(expiresAt).getTime() <= Date.now() ||
					new Date(expiresAt).getTime() > Date.now() + 365 * 86400000)
			)
				throw new Error("Choose an expiry in the future, within one year.");
			let normalized = value.trim();
			if (type === "email-domain") {
				const domains = parseEmailDomains(normalized);
				if (domains.length !== 1)
					throw new Error("Enter exactly one email domain per rule.");
				normalized = domains[0];
			}
			await controlRequest("security/rules/add", {
				method: "POST",
				body: JSON.stringify({
					type,
					value: normalized,
					reason: reason.trim(),
					...(expiresAt ? { expiresAt } : {}),
				}),
			});
			setValue("");
			setReason("");
			setExpiry("");
			toast.success("Block rule saved");
			await queryClient.invalidateQueries({
				queryKey: controlQueryScope(project),
			});
		} catch (error) {
			toast.error(errorMessage(error));
		} finally {
			setBusy(false);
		}
	}
	async function remove() {
		if (!selected) return;
		setBusy(true);
		try {
			await controlRequest("security/rules/remove", {
				method: "POST",
				body: JSON.stringify({ id: selected.id }),
			});
			setSelected(null);
			toast.success("Block rule removed");
			await queryClient.invalidateQueries({
				queryKey: controlQueryScope(project),
			});
		} catch (error) {
			toast.error(errorMessage(error));
		} finally {
			setBusy(false);
		}
	}
	return (
		<Card>
			<CardHeader>
				<CardTitle className="text-base">Block rules</CardTitle>
				<CardDescription>
					Restrict an exact IP address or email domain, with a reason and
					optional expiry.
				</CardDescription>
			</CardHeader>
			<CardContent className="space-y-6">
				{!available && (
					<p className="text-sm text-muted-foreground">
						Block rules are not active on this deployment.
					</p>
				)}
				<form
					className="space-y-4 rounded-lg border p-4"
					onSubmit={(event) => {
						event.preventDefault();
						void add();
					}}
				>
					<fieldset
						disabled={busy || !available}
						className="grid gap-4 sm:grid-cols-2"
					>
						<div className="space-y-2">
							<Label htmlFor="rule-type">Rule type</Label>
							<AppSelect
								id="rule-type"
								className="h-9 w-full rounded-md border bg-background px-3 text-sm"
								value={type}
								onValueChange={(selection) =>
									setType(selection as SecurityRule["type"])
								}
							>
								<AppSelectOption value="ip">IP address</AppSelectOption>
								<AppSelectOption value="email-domain">Email domain</AppSelectOption>
							</AppSelect>
						</div>
						<div className="space-y-2">
							<Label htmlFor="rule-value">
								{type === "ip" ? "Exact IP address" : "Exact email domain"}
							</Label>
							<Input
								id="rule-value"
								required
								maxLength={253}
								value={value}
								onChange={(event) => setValue(event.target.value)}
								placeholder={type === "ip" ? "203.0.113.10" : "example.com"}
							/>
						</div>
						<div className="space-y-2">
							<Label htmlFor="rule-reason">Reason</Label>
							<Input
								id="rule-reason"
								required
								maxLength={200}
								value={reason}
								onChange={(event) => setReason(event.target.value)}
								placeholder="Why access is restricted"
							/>
						</div>
						<div className="space-y-2">
							<Label htmlFor="rule-expiry">Expiry (optional)</Label>
							<Input
								id="rule-expiry"
								type="datetime-local"
								value={expiry}
								onChange={(event) => setExpiry(event.target.value)}
							/>
							<p className="text-xs text-muted-foreground">
								Your device time zone. Leave blank for no expiry.
							</p>
						</div>
					</fieldset>
					<p className="text-xs text-muted-foreground">
						Adding an existing value updates its reason and expiry. Enforcement
						follows the current protection mode.
					</p>
					<Button type="submit" size="sm" disabled={busy || !available}>
						{busy ? "Saving…" : "Save block rule"}
					</Button>
				</form>
				{rules.length ? (
					<div className="overflow-x-auto">
						<Table className="min-w-[660px]">
							<TableHeader>
								<TableRow>
									<TableHead>Rule</TableHead>
									<TableHead>Reason</TableHead>
									<TableHead>Expires</TableHead>
									<TableHead className="text-right">Action</TableHead>
								</TableRow>
							</TableHeader>
							<TableBody>
								{rules.map((rule) => (
									<TableRow key={rule.id}>
										<TableCell>
											<p className="font-mono text-xs break-all">
												{rule.value}
											</p>
											<p className="text-xs text-muted-foreground mt-1">
												{rule.type === "ip" ? "IP address" : "Email domain"}
											</p>
										</TableCell>
										<TableCell className="text-sm max-w-72 break-words">
											{rule.reason}
										</TableCell>
										<TableCell className="text-xs whitespace-nowrap">
											{rule.expiresAt ? (
												<time dateTime={rule.expiresAt}>
													{formatDateTime(rule.expiresAt)}
												</time>
											) : (
												"No expiry"
											)}
										</TableCell>
										<TableCell className="text-right">
											<Button
												type="button"
												variant="outline"
												size="sm"
												disabled={busy || !available}
												onClick={() => setSelected(rule)}
											>
												Remove
											</Button>
										</TableCell>
									</TableRow>
								))}
							</TableBody>
						</Table>
					</div>
				) : (
					<div className="rounded-lg border border-dashed py-8 text-center text-sm text-muted-foreground">
						No active block rules.
					</div>
				)}
				<Dialog
					open={Boolean(selected)}
					onOpenChange={(open) => {
						if (!open && !busy) setSelected(null);
					}}
				>
					<DialogContent>
						<DialogHeader>
							<DialogTitle>Remove this block rule?</DialogTitle>
							<DialogDescription>
								The explicit restriction for {selected?.value} will be removed.
								Other security rules and limits still apply.
							</DialogDescription>
						</DialogHeader>
						<DialogFooter>
							<Button
								type="button"
								variant="outline"
								disabled={busy}
								onClick={() => setSelected(null)}
							>
								Cancel
							</Button>
							<Button
								type="button"
								variant="destructive"
								disabled={busy}
								onClick={() => void remove()}
							>
								{busy ? "Removing…" : "Remove rule"}
							</Button>
						</DialogFooter>
					</DialogContent>
				</Dialog>
			</CardContent>
		</Card>
	);
}

export function ControlSecurity({ project }: { project?: string }) {
	const controlRequest = createControlRequest(project);
	const query = useQuery({
		queryKey: [...controlQueryScope(project), "security"],
		queryFn: ({ signal }) =>
			controlRequest<SecurityResponse>("security", { signal }),
		retry: false,
	});
	if (query.isPending)
		return <ControlLoading label="Loading security policy…" />;
	if (query.isError)
		return (
			<ControlError error={query.error} retry={() => void query.refetch()} />
		);
	const data = query.data;
	const capabilities = [
		{
			key: "credentialStuffing",
			title: "Repeated failed sign-ins",
			description: "IP and account failure limits for authentication attempts.",
		},
		{
			key: "velocity",
			title: "Registration limits",
			description: "Limit registrations and authentication emails from one IP.",
		},
		{
			key: "blockRules",
			title: "IP and email-domain rules",
			description: "Exact rules with reasons and optional expiry.",
		},
		{
			key: "newDeviceNotifications",
			title: "New-device emails",
			description:
				"Notify users after a verified sign-in on an unfamiliar device.",
		},
		{
			key: "botChallenge",
			title: "Bot challenges",
			description: "An interactive bot challenge is not configured.",
		},
		{
			key: "impossibleTravel",
			title: "Impossible-travel detection",
			description: "Location-based sign-in risk detection is not configured.",
		},
		{
			key: "breachedPasswords",
			title: "Breached-password checks",
			description: data.capabilities.breachedPasswords
				? "Known compromised passwords are rejected when creating or changing a password. This check remains enforced in monitor mode."
				: "A compromised-password lookup is not configured.",
		},
	] as const;
	return (
		<div className="space-y-6">
			<div className="flex flex-wrap justify-between items-start gap-3">
				<div>
					<h2 className="text-xl font-semibold">Security</h2>
					<p className="mt-1 text-sm text-muted-foreground">
						Review protections and control authentication risk.
					</p>
				</div>
				<Button
					type="button"
					variant="outline"
					size="sm"
					disabled={query.isFetching}
					onClick={() => void query.refetch()}
				>
					<RefreshCw
						className={`size-3.5 mr-2 ${query.isFetching ? "animate-spin" : ""}`}
						aria-hidden="true"
					/>
					Refresh
				</Button>
			</div>
			<div className="grid gap-3 sm:grid-cols-3">
				{[
					["Blocked requests · last 24 hours", data.stats.blockedRequests],
					["Failed attempts · last 24 hours", data.stats.last24hFailures],
					["Active block rules", data.stats.activeRules],
				].map(([label, value]) => (
					<Card key={String(label)}>
						<CardContent className="pt-5">
							<p className="text-xs text-muted-foreground">{label}</p>
							<p className="text-3xl font-semibold tabular-nums mt-2">
								{Number(value).toLocaleString()}
							</p>
						</CardContent>
					</Card>
				))}
			</div>
			<div
				className={`rounded-lg border p-4 flex items-start gap-3 ${data.policy.mode === "monitor" ? "border-orange-500/40 bg-orange-500/5" : "bg-primary/5"}`}
			>
				{data.policy.mode === "monitor" ? (
					<ShieldOff className="size-5 shrink-0" aria-hidden="true" />
				) : (
					<ShieldCheck className="size-5 shrink-0" aria-hidden="true" />
				)}
				<div>
					<p className="font-medium text-sm">
						{data.policy.mode === "monitor"
							? "Monitor mode"
							: "Enforcement enabled"}
					</p>
					<p className="text-xs text-muted-foreground mt-1">
						{data.policy.mode === "monitor"
							? "Matches are recorded, but requests are not blocked by these protections."
							: "Matching block rules and requests over the configured limits are rejected."}
					</p>
				</div>
			</div>
			<PolicyEditor
				key={`${project ?? ""}:${JSON.stringify(data.policy)}`}
				project={project}
				policy={data.policy}
				notificationsAvailable={data.capabilities.newDeviceNotifications}
			/>
			<BlockRules
				project={project}
				rules={data.rules}
				available={data.capabilities.blockRules}
			/>
			<Card>
				<CardHeader>
					<CardTitle className="text-base">Protection coverage</CardTitle>
					<CardDescription>
						Only configured protections are active. Other risk checks are listed
						separately.
					</CardDescription>
				</CardHeader>
				<CardContent className="grid gap-3 sm:grid-cols-2">
					{capabilities.map(({ key, title, description }) => {
						const configured = data.capabilities[key];
						const enabled =
							configured &&
							(key !== "newDeviceNotifications" ||
								data.policy.newDeviceNotifications);
						const status = !configured
							? "Not active"
							: !enabled
								? "Off"
								: ["credentialStuffing", "velocity", "blockRules"].includes(key) &&
										data.policy.mode === "monitor"
									? "Monitoring"
									: "Active";
						return (
							<div key={key} className="rounded-lg border p-4">
								<div className="flex justify-between items-start gap-3">
									<p className="font-medium text-sm">{title}</p>
									<span
										className={`shrink-0 inline-flex items-center gap-1 text-xs ${enabled ? "text-emerald-700 dark:text-emerald-400" : "text-muted-foreground"}`}
									>
										{enabled && (
											<CheckCircle2 className="size-3.5" aria-hidden="true" />
										)}
										{status}
									</span>
								</div>
								<p className="mt-2 text-xs text-muted-foreground">
									{description}
								</p>
							</div>
						);
					})}
				</CardContent>
			</Card>
		</div>
	);
}

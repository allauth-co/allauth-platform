"use client";

import type { FormEvent } from "react";
import { useEffect, useId, useRef, useState } from "react";
import QRCode from "react-qr-code";
import type { AllAuthClient } from "@/sdk/client";
import { useHostedOrganizationAction } from "./hosted-organization-management";
import { Button } from "./ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";
import {
	Dialog,
	DialogContent,
	DialogDescription,
	DialogFooter,
	DialogHeader,
	DialogTitle,
} from "./ui/dialog";
import { Input } from "./ui/input";
import { Label } from "./ui/label";
import { PasswordInput } from "./ui/password-input";

type Operation = "enable" | "disable" | "regenerate";
const copy = {
	enable: {
		title: "Enable two-factor authentication",
		description: "Set up an authenticator app to secure your account.",
	},
	disable: {
		title: "Disable two-factor authentication",
		description:
			"This removes the authenticator and invalidates your backup codes.",
	},
	regenerate: {
		title: "Regenerate backup codes",
		description: "Generating new backup codes invalidates the previous set.",
	},
};

export function HostedSecurityMfa({
	client,
	enabled,
	hasPassword,
	refresh,
}: {
	client: AllAuthClient;
	enabled: boolean;
	hasPassword: boolean;
	refresh(): Promise<void>;
}) {
	const [operation, setOperation] = useState<Operation | null>(null);
	return (
		<Card>
			<CardHeader>
				<CardTitle>Two-factor authentication</CardTitle>
			</CardHeader>
			<CardContent className="space-y-4">
				<p className="text-sm text-muted-foreground">
					{enabled
						? "Two-factor authentication is enabled."
						: "Add an authenticator app for a second step at sign-in."}
				</p>
				<div className="flex flex-wrap gap-2">
					{enabled ? (
						<>
							<Button
								type="button"
								size="sm"
								variant="outline"
								onClick={() => setOperation("disable")}
							>
								{copy.disable.title}
							</Button>
							<Button
								type="button"
								size="sm"
								variant="outline"
								onClick={() => setOperation("regenerate")}
							>
								{copy.regenerate.title}
							</Button>
						</>
					) : (
						<Button
							type="button"
							size="sm"
							onClick={() => setOperation("enable")}
						>
							{copy.enable.title}
						</Button>
					)}
				</div>
			</CardContent>
			{operation && (
				<MfaDialog
					client={client}
					operation={operation}
					hasPassword={hasPassword}
					refresh={refresh}
					close={() => setOperation(null)}
				/>
			)}
		</Card>
	);
}

type MfaStep =
	| { type: "confirm" }
	| { type: "verify"; uri: string; codes: string[] }
	| { type: "backup"; codes: string[] };

function MfaDialog({
	client,
	operation,
	hasPassword,
	refresh,
	close,
}: {
	client: AllAuthClient;
	operation: Operation;
	hasPassword: boolean;
	refresh(): Promise<void>;
	close(): void;
}) {
	const id = useId();
	const [step, setStep] = useState<MfaStep>({ type: "confirm" });
	const [password, setPassword] = useState("");
	const [code, setCode] = useState("");
	const action = useHostedOrganizationAction();
	function submit(event: FormEvent<HTMLFormElement>) {
		event.preventDefault();
		if (step.type === "backup") return close();
		if (step.type === "verify") {
			if (!/^\d{6}$/.test(code)) return;
			void action.run(async () => {
				const result = await client.twoFactor.verifyTotp({ code });
				setCode("");
				if (result.error) throw new Error(result.error.message);
				if (!result.data?.user)
					throw new Error("The verification could not be confirmed.");
				setStep({ type: "backup", codes: step.codes });
				await refresh();
			}, "Two-factor authentication enabled");
			return;
		}
		if (hasPassword && !password) return;
		const credential = hasPassword ? { password } : {};
		void action.run(
			async () => {
				if (operation === "enable") {
					const result = await client.twoFactor.enable(credential);
					if (result.error) throw new Error(result.error.message);
					if (!result.data?.totpURI || !result.data.backupCodes?.length)
						throw new Error("The authenticator setup could not be confirmed.");
					setStep({
						type: "verify",
						uri: result.data.totpURI,
						codes: result.data.backupCodes,
					});
				} else if (operation === "disable") {
					const result = await client.twoFactor.disable(credential);
					if (result.error) throw new Error(result.error.message);
					if (result.data?.status !== true)
						throw new Error(
							"The authenticator removal could not be confirmed.",
						);
					await refresh();
					close();
				} else {
					const result = await client.twoFactor.generateBackupCodes(credential);
					if (result.error) throw new Error(result.error.message);
					if (!result.data?.backupCodes?.length)
						throw new Error("The new backup codes could not be confirmed.");
					setStep({ type: "backup", codes: result.data.backupCodes });
				}
				setPassword("");
			},
			operation === "enable"
				? "Authenticator setup ready"
				: operation === "disable"
					? "Two-factor authentication disabled"
					: "Backup codes regenerated",
		);
	}
	const title =
		step.type === "backup" ? "Save backup codes" : copy[operation].title;
	const description =
		step.type === "verify"
			? "Scan this QR code with your authenticator app, then enter the six-digit code."
			: step.type === "backup"
				? "Keep these codes somewhere safe. Each code can be used once."
				: copy[operation].description;
	const setupKey =
		step.type === "verify"
			? new URL(step.uri).searchParams.get("secret")
			: null;
	return (
		<Dialog
			open
			onOpenChange={(open) => {
				if (!open && !action.busy) close();
			}}
		>
			<DialogContent className="max-h-[90vh] overflow-y-auto">
				<DialogHeader>
					<DialogTitle>{title}</DialogTitle>
					<DialogDescription>{description}</DialogDescription>
				</DialogHeader>
				<form className="space-y-4" onSubmit={submit}>
					{step.type === "confirm" && hasPassword && (
						<div className="space-y-2">
							<Label htmlFor={`${id}-password`}>Current password</Label>
							<PasswordInput
								id={`${id}-password`}
								autoComplete="current-password"
								value={password}
								onChange={(event) => setPassword(event.target.value)}
								disabled={action.busy}
								required
							/>
						</div>
					)}
					{step.type === "verify" && (
						<div className="space-y-4">
							<div className="mx-auto w-fit bg-white p-3">
								<QRCode
									value={step.uri}
									size={150}
									title="Authenticator setup QR code"
								/>
							</div>
							{setupKey && (
								<div className="space-y-2">
									<p className="text-xs text-muted-foreground">
										Manual setup key
									</p>
									<code className="block break-all text-sm">{setupKey}</code>
									<CopySecret text={setupKey} label="Copy setup key" />
								</div>
							)}
							<div className="space-y-2">
								<Label htmlFor={`${id}-code`}>Authenticator code</Label>
								<Input
									id={`${id}-code`}
									inputMode="numeric"
									autoComplete="one-time-code"
									pattern="[0-9]{6}"
									maxLength={6}
									value={code}
									onChange={(event) => setCode(event.target.value)}
									disabled={action.busy}
									required
								/>
							</div>
						</div>
					)}
					{step.type === "backup" && <BackupCodes codes={step.codes} />}
					{action.error && (
						<p role="alert" className="text-sm text-destructive">
							{action.error}
						</p>
					)}
					<DialogFooter>
						{step.type !== "backup" && (
							<Button
								type="button"
								size="sm"
								variant="outline"
								disabled={action.busy}
								onClick={close}
							>
								Cancel
							</Button>
						)}
						<Button
							type="submit"
							size="sm"
							disabled={action.busy}
							variant={operation === "disable" ? "destructive" : "default"}
						>
							{step.type === "backup"
								? "Done"
								: step.type === "verify"
									? "Verify"
									: copy[operation].title}
						</Button>
					</DialogFooter>
				</form>
			</DialogContent>
		</Dialog>
	);
}

function CopySecret({ text, label }: { text: string; label: string }) {
	const [status, setStatus] = useState("");
	return (
		<>
			<Button
				type="button"
				variant="outline"
				size="sm"
				onClick={async () => {
					try {
						await navigator.clipboard.writeText(text);
						setStatus("Copied");
					} catch {
						setStatus("Unable to copy. Select and copy the text manually.");
					}
				}}
			>
				{label}
			</Button>
			{status && (
				<span role="status" className="text-xs text-muted-foreground">
					{status}
				</span>
			)}
		</>
	);
}

function BackupCodes({ codes }: { codes: string[] }) {
	const text = codes.join("\n");
	const clearPrintView = useRef<(() => void) | null>(null);
	const [printError, setPrintError] = useState(false);
	useEffect(() => () => clearPrintView.current?.(), []);
	function download() {
		const url = URL.createObjectURL(
			new Blob([text], { type: "text/plain;charset=utf-8" }),
		);
		const link = document.createElement("a");
		link.href = url;
		link.download = "backup-codes.txt";
		link.click();
		setTimeout(() => URL.revokeObjectURL(url), 0);
	}
	function print() {
		clearPrintView.current?.();
		setPrintError(false);
		const frame = document.createElement("iframe");
		frame.title = "Print backup codes";
		frame.className = "fixed -left-[10000px] top-0 h-screen w-screen border-0";
		frame.setAttribute("aria-hidden", "true");
		document.body.appendChild(frame);
		const printWindow = frame.contentWindow;
		const printDocument = frame.contentDocument;
		if (!printWindow || !printDocument?.body) {
			frame.remove();
			setPrintError(true);
			return;
		}
		const listing = printDocument.createElement("pre");
		listing.textContent = `${window.location.origin}\n\n${text}`;
		printDocument.title = "Backup codes";
		printDocument.body.appendChild(listing);
		const expire = setTimeout(remove, 60_000);
		function remove() {
			clearTimeout(expire);
			frame.remove();
			clearPrintView.current = null;
		}
		clearPrintView.current = remove;
		printWindow.addEventListener("afterprint", remove, { once: true });
		try {
			printWindow.focus();
			printWindow.print();
		} catch {
			remove();
			setPrintError(true);
		}
	}
	return (
		<div className="space-y-4">
			<ul className="grid grid-cols-2 gap-2 rounded-md border bg-muted/40 p-4 font-mono text-sm">
				{codes.map((code) => (
					<li key={code}>{code}</li>
				))}
			</ul>
			<div className="flex flex-wrap gap-2">
				<CopySecret text={text} label="Copy backup codes" />
				<Button type="button" size="sm" variant="outline" onClick={download}>
					Download backup codes
				</Button>
				<Button type="button" size="sm" variant="outline" onClick={print}>
					Print backup codes
				</Button>
			</div>
			{printError && (
				<p role="alert" className="text-sm text-destructive">
					Unable to print backup codes.
				</p>
			)}
		</div>
	);
}

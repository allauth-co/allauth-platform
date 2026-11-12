"use client";

import type { FormEvent } from "react";
import { useEffect, useId, useRef, useState } from "react";
import type { AllAuthClient } from "@/sdk/client";
import type { AllAuthPasskey } from "@/sdk/client-passkeys";
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

type PasskeyAction =
	| { kind: "add" }
	| { kind: "rename" | "delete"; passkey: AllAuthPasskey };

export function HostedSecurityPasskeys({ client }: { client: AllAuthClient }) {
	const passkeys = client.useListPasskeys();
	const [selected, setSelected] = useState<PasskeyAction | null>(null);
	return (
		<Card>
			<CardHeader className="flex flex-wrap items-center justify-between gap-3">
				<CardTitle>Passkeys</CardTitle>
				<Button
					type="button"
					size="sm"
					variant="outline"
					onClick={() => setSelected({ kind: "add" })}
				>
					Add passkey
				</Button>
			</CardHeader>
			<CardContent className="space-y-4">
				{passkeys.isPending ? (
					<p role="status" className="text-sm text-muted-foreground">
						Loading passkeys…
					</p>
				) : passkeys.error ? (
					<div className="space-y-2">
						<p role="alert" className="text-sm text-destructive">
							{passkeys.error.message}
						</p>
						<Button
							type="button"
							size="sm"
							variant="outline"
							onClick={() => void passkeys.refetch()}
						>
							Try again
						</Button>
					</div>
				) : !passkeys.data?.length ? (
					<p className="text-sm text-muted-foreground">No passkeys added.</p>
				) : (
					passkeys.data.map((passkey) => (
						<div
							key={passkey.id}
							className="flex flex-wrap items-center justify-between gap-3 border-b pb-4 last:border-b-0 last:pb-0"
						>
							<div className="min-w-0 space-y-1">
								<p className="break-all text-sm font-medium">
									{passkey.name || "Passkey"}
								</p>
								{passkey.createdAt && (
									<p className="text-xs text-muted-foreground">
										Added {new Date(passkey.createdAt).toLocaleDateString()}
									</p>
								)}
							</div>
							<div className="flex flex-wrap gap-2">
								<Button
									type="button"
									size="sm"
									variant="outline"
									onClick={() => setSelected({ kind: "rename", passkey })}
								>
									Rename
								</Button>
								<Button
									type="button"
									size="sm"
									variant="outline"
									onClick={() => setSelected({ kind: "delete", passkey })}
								>
									Remove
								</Button>
							</div>
						</div>
					))
				)}
			</CardContent>
			{selected && (
				<PasskeyDialog
					client={client}
					selected={selected}
					close={() => setSelected(null)}
				/>
			)}
		</Card>
	);
}

function PasskeyDialog({
	client,
	selected,
	close,
}: {
	client: AllAuthClient;
	selected: PasskeyAction;
	close(): void;
}) {
	const id = useId();
	const [name, setName] = useState(
		selected.kind === "rename" ? (selected.passkey.name ?? "") : "",
	);
	const ceremony = useRef<AbortController | null>(null);
	const action = useHostedOrganizationAction();
	useEffect(() => () => ceremony.current?.abort(), []);
	const label =
		selected.kind === "add"
			? "Add passkey"
			: selected.kind === "rename"
				? "Rename passkey"
				: "Remove passkey";
	const description =
		selected.kind === "add"
			? "Follow your browser’s instructions to create a passkey."
			: selected.kind === "rename"
				? "Choose a name that helps you recognize this passkey."
				: "This passkey can no longer be used to sign in.";
	function dismiss() {
		if (selected.kind === "add") ceremony.current?.abort();
		if (!action.busy || selected.kind === "add") close();
	}
	function submit(event: FormEvent<HTMLFormElement>) {
		event.preventDefault();
		if (selected.kind === "rename" && !name.trim()) return;
		void action.run(
			async () => {
				if (selected.kind === "add") {
					const controller = new AbortController();
					ceremony.current = controller;
					const result = await client.passkey.addPasskey({
						name: name.trim() || undefined,
						fetchOptions: { signal: controller.signal },
					});
					if (controller.signal.aborted)
						throw new Error("Passkey registration cancelled.");
					if (result.error) throw new Error(result.error.message);
					if (!result.data?.id)
						throw new Error("The passkey could not be confirmed.");
				} else if (selected.kind === "rename") {
					const result = await client.passkey.updatePasskey({
						id: selected.passkey.id,
						name: name.trim(),
					});
					if (result.error) throw new Error(result.error.message);
					if (result.data?.passkey.id !== selected.passkey.id)
						throw new Error("The passkey change could not be confirmed.");
				} else {
					const result = await client.passkey.deletePasskey({
						id: selected.passkey.id,
					});
					if (result.error) throw new Error(result.error.message);
					if (result.data?.status !== true)
						throw new Error("The passkey removal could not be confirmed.");
				}
				close();
			},
			selected.kind === "add"
				? "Passkey added"
				: selected.kind === "rename"
					? "Passkey renamed"
					: "Passkey removed",
		);
	}
	return (
		<Dialog
			open
			onOpenChange={(open) => {
				if (!open) dismiss();
			}}
		>
			<DialogContent>
				<DialogHeader>
					<DialogTitle>{label}</DialogTitle>
					<DialogDescription>{description}</DialogDescription>
				</DialogHeader>
				<form className="space-y-4" onSubmit={submit}>
					{selected.kind !== "delete" && (
						<div className="space-y-2">
							<Label htmlFor={id}>
								Name{selected.kind === "add" && " (optional)"}
							</Label>
							<Input
								id={id}
								value={name}
								onChange={(event) => setName(event.target.value)}
								required={selected.kind === "rename"}
								disabled={action.busy}
								maxLength={160}
							/>
						</div>
					)}
					{action.error && (
						<p role="alert" className="text-sm text-destructive">
							{action.error}
						</p>
					)}
					<DialogFooter>
						<Button
							type="button"
							size="sm"
							variant="outline"
							onClick={dismiss}
							disabled={action.busy && selected.kind !== "add"}
						>
							Cancel
						</Button>
						<Button
							type="submit"
							size="sm"
							variant={selected.kind === "delete" ? "destructive" : "default"}
							disabled={action.busy}
						>
							{label}
						</Button>
					</DialogFooter>
				</form>
			</DialogContent>
		</Dialog>
	);
}

"use client";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";
import { authClient } from "@/lib/auth-client";
import { useConfiguration } from "@/lib/configuration-client";
import { errorMessage } from "@/lib/shared";
import {
	Card,
	CardContent,
	CardDescription,
	CardHeader,
	CardTitle,
} from "./ui/card";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
export function ApiKeys() {
	const { data: config } = useConfiguration();
	const queryClient = useQueryClient();
	const [name, setName] = useState("");
	const [secret, setSecret] = useState("");
	const [busy, setBusy] = useState(false);
	const keys = useQuery({
		queryKey: ["api-keys"],
		enabled: Boolean(config?.apiKeys),
		queryFn: async () => {
			const { data, error } = await authClient.apiKey.list();
			if (error) throw new Error(error.message);
			return data;
		},
	});
	const run = async (action: () => Promise<void>) => {
		setBusy(true);
		try {
			await action();
			await queryClient.invalidateQueries({ queryKey: ["api-keys"] });
		} catch (e) {
			toast.error(errorMessage(e));
		} finally {
			setBusy(false);
		}
	};
	if (!config?.apiKeys) return null;
	return (
		<Card>
			<CardHeader>
				<CardTitle>API keys</CardTitle>
				<CardDescription>
					Create personal credentials for trusted integrations. Copy new keys
					now; they cannot be shown again.
				</CardDescription>
			</CardHeader>
			<CardContent className="space-y-4">
				{secret && (
					<div className="bg-muted p-4 rounded-md space-y-2">
						<p className="text-sm font-medium">Your new API key</p>
						<code className="block break-all text-xs">{secret}</code>
						<Button
							size="sm"
							variant="outline"
							onClick={() =>
								void navigator.clipboard
									.writeText(secret)
									.then(() => toast.success("Copied"))
									.catch(() => toast.error("Unable to copy"))
							}
						>
							Copy key
						</Button>
						<Button size="sm" variant="ghost" onClick={() => setSecret("")}>
							Dismiss
						</Button>
					</div>
				)}
				<form
					className="flex gap-2"
					onSubmit={(e) => {
						e.preventDefault();
						void run(async () => {
							const { data, error } = await authClient.apiKey.create({
								name,
								expiresIn: 60 * 60 * 24 * 90,
							});
							if (error) throw new Error(error.message);
							if (!data?.key) throw new Error("No key was returned");
							setSecret(data.key);
							setName("");
						});
					}}
				>
					<Input
						aria-label="API key name"
						placeholder="Integration name"
						value={name}
						onChange={(e) => setName(e.target.value)}
						required
						maxLength={100}
					/>
					<Button disabled={busy}>Create key</Button>
				</form>
				{keys.error && (
					<p className="text-sm text-destructive" role="alert">
						{errorMessage(keys.error)}
					</p>
				)}
				{keys.data?.apiKeys.map((key) => (
					<div
						className="flex justify-between gap-3 border-t py-3"
						key={key.id}
					>
						<div>
							<p className="text-sm font-medium">{key.name || "API key"}</p>
							<p className="text-xs text-muted-foreground">
								{key.start}… · {key.enabled ? "Active" : "Disabled"}
							</p>
						</div>
						<Button
							size="sm"
							variant="outline"
							disabled={busy}
							onClick={() => {
								if (
									window.confirm(
										"Revoke this API key? Integrations using it will stop working.",
									)
								)
									void run(async () => {
										const { error } = await authClient.apiKey.delete({
											keyId: key.id,
										});
										if (error) throw new Error(error.message);
										toast.success("Key revoked");
									});
							}}
						>
							Revoke
						</Button>
					</div>
				))}
			</CardContent>
		</Card>
	);
}

"use client";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { toast } from "sonner";
import * as z from "zod";
import { authClient } from "@/lib/auth-client";
import { useConfiguration } from "@/lib/configuration-client";
import { hostedAccountRequest } from "@/lib/domains/hosted-account-transport";
import type { AllAuthClient } from "@/sdk/client";
import { useHostedOrganizationClient } from "./hosted-organization-client";
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
type PersonalKey = {
	id: string;
	name?: string | null;
	start?: string | null;
	enabled?: boolean | null;
};
type KeyActions = {
	list(signal: AbortSignal): Promise<PersonalKey[]>;
	create(name: string): Promise<string>;
	revoke(keyId: string): Promise<void>;
};
const keyLifetime = 60 * 60 * 24 * 90;
const listResponse = z.object({
	apiKeys: z.array(
		z.object({
			id: z.string().min(1),
			name: z.string().nullish(),
			start: z.string().nullish(),
			enabled: z.boolean().nullish(),
		}),
	),
});
const createResponse = z.object({ key: z.string().min(1) });
const revokeResponse = z.object({ success: z.literal(true) });

const hostedKeys: KeyActions = {
	async list(signal) {
		const result = listResponse.safeParse(
			await hostedAccountRequest("api-key/list", undefined, signal),
		);
		if (!result.success)
			throw new Error("The API key list could not be loaded.");
		return result.data.apiKeys;
	},
	async create(name) {
		const result = createResponse.safeParse(
			await hostedAccountRequest("api-key/create", {
				name,
				expiresIn: keyLifetime,
			}),
		);
		if (!result.success) throw new Error("No key was returned");
		return result.data.key;
	},
	async revoke(keyId) {
		if (
			!revokeResponse.safeParse(
				await hostedAccountRequest("api-key/delete", { keyId }),
			).success
		)
			throw new Error("The key revocation could not be confirmed.");
	},
};
const legacyKeys: KeyActions = {
	async list() {
		const { data, error } = await authClient.apiKey.list();
		if (error) throw new Error(error.message);
		return data?.apiKeys ?? [];
	},
	async create(name) {
		const { data, error } = await authClient.apiKey.create({
			name,
			expiresIn: keyLifetime,
		});
		if (error) throw new Error(error.message);
		if (!data?.key) throw new Error("No key was returned");
		return data.key;
	},
	async revoke(keyId) {
		const { error } = await authClient.apiKey.delete({ keyId });
		if (error) throw new Error(error.message);
	},
};

export function ApiKeys() {
	const client = useHostedOrganizationClient();
	return client ? (
		<HostedApiKeys client={client} />
	) : (
		<ApiKeySettings actions={legacyKeys} />
	);
}

function HostedApiKeys({ client }: { client: AllAuthClient }) {
	const { data } = client.useSession();
	return data ? (
		<ApiKeySettings
			key={data.session.id}
			actions={hostedKeys}
			sessionId={data.session.id}
		/>
	) : null;
}

function ApiKeySettings({
	actions,
	sessionId,
}: {
	actions: KeyActions;
	sessionId?: string;
}) {
	const { data: config } = useConfiguration();
	const queryClient = useQueryClient();
	const [name, setName] = useState("");
	const [secret, setSecret] = useState("");
	const [busy, setBusy] = useState(false);
	const changing = useRef(false);
	const queryKey = sessionId ? ["api-keys", "hosted", sessionId] : ["api-keys"];
	const keys = useQuery({
		queryKey,
		enabled: Boolean(config?.apiKeys),
		queryFn: ({ signal }) => actions.list(signal),
	});
	const run = async (action: () => Promise<void>) => {
		if (changing.current) return;
		changing.current = true;
		setBusy(true);
		try {
			await action();
			await queryClient.invalidateQueries({ queryKey });
		} catch (e) {
			toast.error(errorMessage(e));
		} finally {
			changing.current = false;
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
							setSecret(await actions.create(name));
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
				{keys.data?.map((key) => (
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
										await actions.revoke(key.id);
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

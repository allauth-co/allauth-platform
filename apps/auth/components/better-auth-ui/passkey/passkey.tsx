// Adapted from Better Auth UI official radix-nova registry (MIT). See ATTRIBUTION.md.
"use client";

import { useAuthPlugin } from "@better-auth-ui/react";
import { useAuth } from "@/components/better-auth-ui/lib/use-auth";
import { Fingerprint, Pencil, X } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/better-auth-ui/ui/button";
import {
	Item,
	ItemActions,
	ItemContent,
	ItemDescription,
	ItemMedia,
	ItemTitle,
} from "@/components/better-auth-ui/ui/item";
import { passkeyPlugin } from "@/components/better-auth-ui/lib/passkey-plugin";

import {
	DeletePasskeyDialog,
	type ListedPasskey,
} from "./delete-passkey-dialog";
import { RenamePasskeyDialog } from "./rename-passkey-dialog";

export type PasskeyProps = {
	passkey: ListedPasskey;
};

export function Passkey({ passkey }: PasskeyProps) {
	const { localization } = useAuth();
	const { localization: passkeyLocalization } = useAuthPlugin(passkeyPlugin);
	const [deleteOpen, setDeleteOpen] = useState(false);
	const [renameOpen, setRenameOpen] = useState(false);

	const passkeyName = passkey.name || passkeyLocalization.passkey;

	return (
		<Item>
			<ItemMedia variant="icon">
				<Fingerprint />
			</ItemMedia>
			<ItemContent>
				<ItemTitle>{passkeyName}</ItemTitle>
				<ItemDescription>
					{new Date(passkey.createdAt).toLocaleString(undefined, {
						dateStyle: "medium",
						timeStyle: "short",
					})}
				</ItemDescription>
			</ItemContent>
			<ItemActions>
				<Button variant="outline" size="sm" onClick={() => setRenameOpen(true)}>
					<Pencil />
					{passkeyLocalization.renamePasskey}
				</Button>
				<Button
					variant="outline"
					size="sm"
					onClick={() => setDeleteOpen(true)}
					aria-label={passkeyLocalization.deletePasskey.replace(
						"{{name}}",
						passkeyName,
					)}
				>
					<X />

					{localization.settings.delete}
				</Button>

				<DeletePasskeyDialog
					open={deleteOpen}
					onOpenChange={setDeleteOpen}
					passkey={passkey}
				/>
				<RenamePasskeyDialog
					open={renameOpen}
					onOpenChange={setRenameOpen}
					passkey={passkey}
				/>
			</ItemActions>
		</Item>
	);
}

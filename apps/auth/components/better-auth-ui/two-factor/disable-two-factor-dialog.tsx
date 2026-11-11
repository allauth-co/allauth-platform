// Adapted from Better Auth UI official radix-nova registry (MIT). See ATTRIBUTION.md.
"use client";

import type { TwoFactorAuthClient } from "@better-auth-ui/core/plugins/two-factor";
import { useAuthPlugin } from "@better-auth-ui/react";
import { useAuth } from "@/components/better-auth-ui/lib/use-auth";
import { useDisableTwoFactor } from "@better-auth-ui/react/plugins/two-factor";
import { ShieldAlert } from "lucide-react";
import { toast } from "sonner";

import {
	AlertDialog,
	AlertDialogCancel,
	AlertDialogContent,
	AlertDialogDescription,
	AlertDialogFooter,
	AlertDialogHeader,
	AlertDialogMedia,
	AlertDialogTitle,
} from "@/components/better-auth-ui/ui/alert-dialog";
import {
	Field,
	FieldError,
	FieldLabel,
} from "@/components/better-auth-ui/ui/field";
import { Input } from "@/components/ui/input";
import { twoFactorPlugin } from "@/components/better-auth-ui/lib/two-factor-plugin";
import { useTwoFactorPasswordRequirement } from "@/components/better-auth-ui/lib/use-two-factor-password";
import { useAuthForm } from "../auth-form";
import { AccountDataError, AccountSignInRequired } from "../settings/security/account-data-state";

export type DisableTwoFactorDialogProps = {
	open: boolean;
	onOpenChange: (open: boolean) => void;
};

/**
 * Confirm turning two-factor off.
 *
 * @param open - Whether the dialog is open.
 * @param onOpenChange - Called when the dialog requests an open state change.
 */
export function DisableTwoFactorDialog({
	open,
	onOpenChange,
}: DisableTwoFactorDialogProps) {
	const { authClient, localization } = useAuth();
	const { localization: twoFactorLocalization } =
		useAuthPlugin(twoFactorPlugin);
	const { isPending: isResolvingPasswordRequirement, requiresPassword, requiresSignIn, error: passwordRequirementError, refetch: retryPasswordRequirement, isFetching: refetchingPasswordRequirement } =
		useTwoFactorPasswordRequirement();

	const { mutateAsync: disableTwoFactor, isPending: isDisabling } =
		useDisableTwoFactor(authClient as TwoFactorAuthClient, {
			onSuccess: () => {
				toast.success(twoFactorLocalization.twoFactorDisabled);
				onOpenChange(false);
			},
		});

	const isPending = isDisabling || isResolvingPasswordRequirement;

	const form = useAuthForm({
		defaultValues: { password: "" },
		onSubmit: async ({ value }) => {
			if (passwordRequirementError || requiresSignIn) return;
			await disableTwoFactor(
				requiresPassword ? { password: value.password } : {},
			);
		},
	});

	return (
		<AlertDialog open={open} onOpenChange={onOpenChange}>
			<AlertDialogContent>
				<form.AppForm>
					<form.AuthFormRoot className="flex flex-col gap-6">
						<AlertDialogHeader>
							<AlertDialogMedia className="bg-destructive/10 text-destructive dark:bg-destructive/20 dark:text-destructive">
								<ShieldAlert />
							</AlertDialogMedia>

							<AlertDialogTitle>
								{twoFactorLocalization.disableTwoFactor}
							</AlertDialogTitle>

							<AlertDialogDescription>
								{requiresPassword
									? twoFactorLocalization.passwordConfirmation
									: twoFactorLocalization.twoFactorDescription}
							</AlertDialogDescription>
						</AlertDialogHeader>
						{passwordRequirementError && <AccountDataError message="Unable to load account security requirements." retry={() => retryPasswordRequirement()} isFetching={refetchingPasswordRequirement} />}
						{requiresSignIn && <AccountSignInRequired />}

						{requiresPassword && !requiresSignIn && (
							<form.AppField name="password">
								{(field) => (
									<Field>
										<FieldLabel htmlFor="disable-two-factor-password">
											{localization.auth.password}
										</FieldLabel>

										<Input
											id="disable-two-factor-password"
											name={field.name}
											type="password"
											autoComplete="current-password"
											autoFocus
											required
											placeholder={localization.auth.passwordPlaceholder}
											disabled={isPending}
											value={field.state.value}
											onBlur={field.handleBlur}
											onChange={(event) =>
												field.handleChange(event.target.value)
											}
										/>

										<FieldError />
									</Field>
								)}
							</form.AppField>
						)}

						<AlertDialogFooter>
							<AlertDialogCancel disabled={isPending}>
								{localization.settings.cancel}
							</AlertDialogCancel>

							<form.AuthFormSubmitButton
								isPending={isPending}
								variant="destructive"
								disabled={isPending || Boolean(passwordRequirementError) || requiresSignIn}
							>
								{twoFactorLocalization.disableTwoFactor}
							</form.AuthFormSubmitButton>
						</AlertDialogFooter>
					</form.AuthFormRoot>
				</form.AppForm>
			</AlertDialogContent>
		</AlertDialog>
	);
}

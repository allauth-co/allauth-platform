// Adapted from Better Auth UI official radix-nova registry (MIT). See ATTRIBUTION.md.
"use client";

import type { MultiSessionAuthClient } from "@better-auth-ui/core/plugins/multi-session";
import { useSession } from "@better-auth-ui/react";
import { useAuth } from "@/components/better-auth-ui/lib/use-auth";
import { useSetActiveSession } from "@better-auth-ui/react/plugins/multi-session";
import {
	ChevronsUpDown,
	LogIn,
	LogOut,
	Settings,
	UserPlus2,
} from "lucide-react";
import { isValidElement, type ReactElement, type ReactNode } from "react";

import { buttonVariants } from "@/components/better-auth-ui/ui/button";
import {
	DropdownMenu,
	DropdownMenuContent,
	DropdownMenuGroup,
	DropdownMenuItem,
	DropdownMenuLabel,
	DropdownMenuSeparator,
	DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { cn } from "cn";
import { UserAvatar } from "./user-avatar";
import { UserView } from "./user-view";
import "./user-button.css";

/** Auth states a `UserButton` link can be visible in. */
export type UserButtonLinkVisibility =
	| "authenticated"
	| "unauthenticated"
	| "always";

/** A simple link entry rendered as a `DropdownMenuItem` in the `UserButton` menu. */
export type UserButtonLink = {
	/** Visible label. */
	label: ReactNode;
	/** Optional supporting text below the label. */
	description?: ReactNode;
	/** Destination URL. */
	href: string;
	/** Optional leading icon. Sized/coloured to match built-in items. */
	icon?: ReactNode;
	/** Forwarded to the underlying `DropdownMenuItem`. */
	variant?: "default" | "destructive";
	/**
	 * When this link is visible based on auth state.
	 * @default "always"
	 */
	visibility?: UserButtonLinkVisibility;
};

export type UserButtonProps = {
	className?: string;
	align?: "center" | "end" | "start" | undefined;
	side?: "top" | "right" | "bottom" | "left";
	sideOffset?: number;
	size?: "default" | "icon";
	variant?:
		| "default"
		| "destructive"
		| "ghost"
		| "link"
		| "outline"
		| "secondary";
	/** Additional menu entries rendered above the built-in items. */
	links?: (UserButtonLink | ReactElement)[];
	/** Hide the built-in "Settings" link. Useful when replacing it via `links`. */
	hideSettings?: boolean;
	/** Optional non-interactive attribution rendered beneath the menu actions. */
	menuFooter?: ReactNode;
};

function renderUserLink(
	link: UserButtonLink | ReactElement,
	navigate: (options: { to: string; replace?: boolean }) => void,
	fallbackKey: string,
): ReactNode {
	if (isValidElement(link)) return link;

	const { label, description, href, icon, variant } = link;
	return (
		<DropdownMenuItem
			key={fallbackKey}
			className="allauth-user-menu-action"
			variant={variant}
			onClick={() => navigate({ to: href })}
		>
			{icon && <span className="allauth-user-menu-action-icon">{icon}</span>}
			<span className="allauth-user-menu-action-copy">
				<span className="allauth-user-menu-action-label">{label}</span>
				{description && (
					<span className="allauth-user-menu-action-description">
						{description}
					</span>
				)}
			</span>
		</DropdownMenuItem>
	);
}

/**
 * Render an account avatar or button with an identity card and authentication actions.
 *
 * Includes user profile, settings and plugin links, and sign-in/sign-up/sign-out actions.
 *
 * @param className - Additional CSS classes applied to the button trigger
 * @param align - Alignment of the dropdown menu relative to the trigger
 * @param side - Preferred side of the trigger on which to show the dropdown menu
 * @param sideOffset - Offset between the trigger and the dropdown menu
 * @param size - "icon" renders only the avatar; "default" renders a full button with label and chevron
 * @param variant - Visual variant of the trigger button
 * @param links - Additional menu entries rendered above the built-in items
 * @param hideSettings - Hide the built-in "Settings" link
 * @param menuFooter - Optional non-interactive attribution below the menu actions
 * @returns The dropdown menu component with user actions
 */
export function UserButton({
	className,
	align,
	side,
	sideOffset,
	size = "default",
	variant = "ghost",
	links,
	hideSettings = false,
	menuFooter,
}: UserButtonProps) {
	const { authClient, basePaths, viewPaths, localization, plugins, navigate, signUpEnabled } =
		useAuth<MultiSessionAuthClient>();

	const { isPending: settingActiveSession } = useSetActiveSession(authClient);
	const { data: session, isPending: sessionPending } = useSession(authClient);

	const userLinks = links?.flatMap((link, index) => {
		if (!isValidElement(link)) {
			const visibility = link.visibility ?? "always";
			if (visibility === "authenticated" && !session) return [];
			if (visibility === "unauthenticated" && session) return [];
		}
		return [
			renderUserLink(link, navigate, `user-button-link-${index.toString()}`),
		];
	});

	// Whether anything renders between the user info label and the
	// sign-out item, so the leading separator isn't shown with nothing
	// to separate (see #439).
	const hasSessionMenuItems =
		(userLinks?.length ?? 0) > 0 ||
		!hideSettings ||
		plugins.some((plugin) => (plugin.userMenuItems?.length ?? 0) > 0);

	return (
		<DropdownMenu>
			<DropdownMenuTrigger
				type="button"
				aria-label={size === "icon" ? localization.auth.account : undefined}
				className={
					size === "icon"
						? cn("rounded-full", className)
						: cn(
								buttonVariants({ variant, size: "lg" }),
								"py-2.5 h-auto font-normal",
								className,
							)
				}
			>
				{size === "icon" ? (
					<UserAvatar />
				) : (
					<>
						{session || sessionPending || settingActiveSession ? (
							<UserView isPending={!!settingActiveSession} />
						) : (
							<>
								<UserAvatar />

								<div className="grid flex-1 text-left text-sm leading-tight">
									{localization.auth.account}
								</div>
							</>
						)}

						<ChevronsUpDown className="ml-auto size-4" />
					</>
				)}
			</DropdownMenuTrigger>

			<DropdownMenuContent
				className="allauth-user-menu-panel"
				side={side}
				sideOffset={sideOffset}
				align={align}
				collisionPadding={12}
			>
				{session && (
					<>
						<DropdownMenuGroup>
							<DropdownMenuLabel className="allauth-user-menu-identity">
								<UserView avatarClassName="size-10" />
							</DropdownMenuLabel>
						</DropdownMenuGroup>

						{hasSessionMenuItems && <DropdownMenuSeparator />}
					</>
				)}

				{session ? (
					<>
						{userLinks}

						{!hideSettings && (
							<DropdownMenuItem
								className="allauth-user-menu-action"
								onClick={() =>
									navigate({
										to: `${basePaths.settings}/${viewPaths.settings.account}`,
									})
								}
							>
								<span className="allauth-user-menu-action-icon">
									<Settings aria-hidden="true" />
								</span>

								{localization.settings.settings}
							</DropdownMenuItem>
						)}

						{plugins.flatMap((plugin) =>
							plugin.userMenuItems?.map((Item, index) => (
								<Item key={`${plugin.id}-${index.toString()}`} />
							)),
						)}

						<DropdownMenuSeparator />

						<DropdownMenuItem
							className="allauth-user-menu-action allauth-user-menu-sign-out"
							onClick={() =>
								navigate({
									to: `${basePaths.auth}/${viewPaths.auth.signOut}`,
								})
							}
						>
							<span className="allauth-user-menu-action-icon">
								<LogOut aria-hidden="true" />
							</span>

							{localization.auth.signOut}
						</DropdownMenuItem>
					</>
				) : (
					<>
						{userLinks}

						<DropdownMenuItem
							className="allauth-user-menu-action"
							onClick={() =>
								navigate({
									to: `${basePaths.auth}/${viewPaths.auth.signIn}`,
								})
							}
						>
							<LogIn className="text-muted-foreground" />

							{localization.auth.signIn}
						</DropdownMenuItem>

						{signUpEnabled !== false && <DropdownMenuItem
							className="allauth-user-menu-action"
							onClick={() =>
								navigate({
									to: `${basePaths.auth}/${viewPaths.auth.signUp}`,
								})
							}
						>
							<UserPlus2 className="text-muted-foreground" />

							{localization.auth.signUp}
						</DropdownMenuItem>}

						{plugins.flatMap((plugin) =>
							plugin.userMenuItems?.map((Item, index) => (
								<Item key={`${plugin.id}-${index.toString()}`} />
							)),
						)}
					</>
				)}
				{menuFooter && (
					<div className="allauth-user-menu-footer">{menuFooter}</div>
				)}
			</DropdownMenuContent>
		</DropdownMenu>
	);
}

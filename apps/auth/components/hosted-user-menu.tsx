"use client";

import { LogOut, Settings, ShieldCheck, UserRound } from "lucide-react";
import Link from "next/link";
import type { AllAuthUser } from "@/sdk/client";
import { LogoIcon } from "./logo";
import { Avatar, AvatarFallback, AvatarImage } from "./ui/avatar";
import {
	DropdownMenu,
	DropdownMenuContent,
	DropdownMenuGroup,
	DropdownMenuItem,
	DropdownMenuLabel,
	DropdownMenuSeparator,
	DropdownMenuTrigger,
} from "./ui/dropdown-menu";
import "./better-auth-ui/user/user-button.css";

type HostedUser = AllAuthUser & { username?: string; displayUsername?: string };

function AccountAvatar({ user, large }: { user: HostedUser; large?: boolean }) {
	const initials = (user.username || user.name || user.email)
		.slice(0, 2)
		.toUpperCase();
	return (
		<Avatar className={large ? "size-10" : undefined}>
			<AvatarImage src={user.image ?? undefined} alt="" />
			<AvatarFallback
				className="text-sm text-muted-foreground"
				aria-hidden="true"
			>
				{initials || <UserRound className="size-4" />}
			</AvatarFallback>
		</Avatar>
	);
}

/** The hosted header supplies the verified identity without using the native browser client. */
export function HostedUserMenu({
	user,
	signOutHref,
}: {
	user: HostedUser;
	signOutHref: string;
}) {
	const primary = user.displayUsername || user.name || user.email;
	return (
		<DropdownMenu>
			<DropdownMenuTrigger
				type="button"
				className="account-user-button allauth-user-trigger"
				aria-label="Account"
			>
				<AccountAvatar user={user} />
			</DropdownMenuTrigger>
			<DropdownMenuContent
				className="allauth-user-menu-panel"
				align="end"
				sideOffset={10}
				collisionPadding={12}
			>
				<DropdownMenuGroup>
					<DropdownMenuLabel className="allauth-user-menu-identity">
						<div className="flex min-w-0 items-center">
							<AccountAvatar user={user} large />
							<div className="grid min-w-0 flex-1 text-left text-sm leading-tight">
								<span className="truncate font-semibold">{primary}</span>
								{primary !== user.email && (
									<span className="truncate text-xs text-muted-foreground">
										{user.email}
									</span>
								)}
							</div>
						</div>
					</DropdownMenuLabel>
				</DropdownMenuGroup>
				<DropdownMenuSeparator />
				{(
					[
						[
							"/account",
							"Manage account",
							"Profile and account settings",
							Settings,
						],
						[
							"/account/security",
							"Account security",
							"Sign-in methods and active sessions",
							ShieldCheck,
						],
					] as const
				).map(([href, label, description, Icon]) => (
					<DropdownMenuItem
						key={href}
						className="allauth-user-menu-action"
						asChild
					>
						<Link href={href}>
							<span className="allauth-user-menu-action-icon">
								<Icon aria-hidden="true" />
							</span>
							<span className="allauth-user-menu-action-copy">
								<span className="allauth-user-menu-action-label">{label}</span>
								<span className="allauth-user-menu-action-description">
									{description}
								</span>
							</span>
						</Link>
					</DropdownMenuItem>
				))}
				<DropdownMenuSeparator />
				<DropdownMenuItem
					className="allauth-user-menu-action allauth-user-menu-sign-out"
					asChild
				>
					<Link href={signOutHref}>
						<span className="allauth-user-menu-action-icon">
							<LogOut aria-hidden="true" />
						</span>
						Sign out
					</Link>
				</DropdownMenuItem>
				<div className="allauth-user-menu-footer">
					<span>Secured by</span>
					<LogoIcon aria-hidden="true" />
					<span className="allauth-user-menu-brand">AllAuth</span>
				</div>
			</DropdownMenuContent>
		</DropdownMenu>
	);
}

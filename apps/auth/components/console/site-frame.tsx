"use client";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";
import { AccountShell } from "./account-shell";
import { isPublicProductPath } from "@/lib/public-site";
export function SiteFrame({ children }: { children: ReactNode }) {
	const pathname = usePathname();
	if (isPublicProductPath(pathname)) return children;
	if (pathname === "/admin" || pathname.startsWith("/admin/"))
		return <main className="console-root">{children}</main>;
	return <AccountShell>{children}</AccountShell>;
}

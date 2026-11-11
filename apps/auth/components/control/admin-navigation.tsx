"use client";

import Link from "next/link";
import { usePathname, useSearchParams } from "next/navigation";
import { managementHref, projectFromSearch } from "./helpers";

export function AdminNavigation({
	links,
}: {
	links: readonly (readonly [string, string])[];
}) {
	const searchParams = useSearchParams();
	const pathname = usePathname();
	const selections = searchParams.getAll("project");
	const project = projectFromSearch(selections.length ? selections : undefined);
	return (
		<nav
			aria-label="Administration"
			className="flex flex-wrap gap-5 border-b pb-4 text-sm"
		>
			{links.map(([href, label]) => (
				<Link
					href={managementHref(href, project)}
					key={href}
					aria-current={pathname === href ? "page" : undefined}
					className={pathname === href ? "font-semibold" : "hover:underline"}
				>
					{label}
				</Link>
			))}
		</nav>
	);
}

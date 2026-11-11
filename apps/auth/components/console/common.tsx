"use client";

import { ChevronLeft, ChevronRight, Copy, Search, X } from "lucide-react";
import { useEffect, useId, useRef } from "react";
import type { ReactNode } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";

export async function managementRequest<T>(
	path: string,
	init?: RequestInit,
): Promise<T> {
	const response = await fetch(path, {
		...init,
		credentials: "same-origin",
		cache: "no-store",
		headers: {
			Accept: "application/json",
			...(init?.body ? { "content-type": "application/json" } : {}),
			...init?.headers,
		},
	});
	const data: unknown = await response.json();
	if (!response.ok)
		throw new Error(
			data &&
				typeof data === "object" &&
				"error" in data &&
				typeof data.error === "string"
				? data.error
				: response.status === 403
					? "You do not have permission to perform this action."
					: "The request could not be completed.",
		);
	return data as T;
}

export function PageHeading({
	title,
	description,
	children,
}: {
	title: string;
	description?: string;
	children?: ReactNode;
}) {
	return (
		<div className="console-page-heading">
			<div>
				<h1>{title}</h1>
				{description && <p>{description}</p>}
			</div>
			<div className="flex flex-wrap items-center gap-2">{children}</div>
		</div>
	);
}
export function SearchField({
	value,
	onChange,
	placeholder = "Search…",
}: {
	value: string;
	onChange: (value: string) => void;
	placeholder?: string;
}) {
	return (
		<div className="console-search">
			<Search size={15} aria-hidden="true" />
			<input
				aria-label={placeholder}
				placeholder={placeholder}
				value={value}
				onChange={(event) => onChange(event.target.value)}
				maxLength={128}
			/>
			{value && (
				<button
					type="button"
					aria-label="Clear search"
					onClick={() => onChange("")}
				>
					<X size={14} />
				</button>
			)}
		</div>
	);
}
export function StateMessage({
	loading,
	error,
	empty,
	children,
}: {
	loading?: boolean;
	error?: unknown;
	empty?: boolean;
	children?: ReactNode;
}) {
	if (loading)
		return (
			<div role="status" className="console-empty">
				<span className="console-loading" />
				Loading…
			</div>
		);
	if (error)
		return (
			<div role="alert" className="console-empty text-destructive">
				{error instanceof Error
					? error.message
					: "Unable to load this information."}
			</div>
		);
	if (empty)
		return (
			<div className="console-empty">
				{children || "No results found. Try changing your filters."}
			</div>
		);
	return null;
}
export function Pagination({
	total,
	offset,
	limit = 25,
	count,
	busy,
	onOffset,
}: {
	total: number;
	offset: number;
	limit?: number;
	count: number;
	busy?: boolean;
	onOffset: (offset: number) => void;
}) {
	return (
		<div className="console-pagination">
			<span>
				{total
					? `${offset + 1}–${offset + count} of ${total.toLocaleString()}`
					: "0 results"}
			</span>
			<div className="flex items-center gap-2">
				<Button
					type="button"
					size="sm"
					variant="outline"
					aria-label="Previous page"
					disabled={offset === 0 || busy}
					onClick={() => onOffset(Math.max(0, offset - limit))}
				>
					<ChevronLeft size={14} />
				</Button>
				<span>Page {Math.floor(offset / limit) + 1}</span>
				<Button
					type="button"
					size="sm"
					variant="outline"
					aria-label="Next page"
					disabled={offset + limit >= total || busy}
					onClick={() => onOffset(offset + limit)}
				>
					<ChevronRight size={14} />
				</Button>
			</div>
		</div>
	);
}
export function Badge({
	children,
	tone = "neutral",
}: {
	children: ReactNode;
	tone?: "neutral" | "success" | "danger" | "blue";
}) {
	return (
		<span className={`console-badge console-badge-${tone}`}>{children}</span>
	);
}
export function Identity({
	name,
	email,
	image,
}: {
	name: string;
	email?: string;
	image?: string | null;
}) {
	const primary = name.trim() || email?.trim() || "User";
	const secondary = email?.trim();
	return (
		<div className="console-identity">
			{image ? (
				<img src={image} alt="" className="console-avatar" />
			) : (
				<span className="console-avatar">{primary.slice(0, 2).toUpperCase()}</span>
			)}
			<span className="min-w-0">
				<strong>{primary}</strong>
				{secondary && secondary !== primary && <small>{secondary}</small>}
			</span>
		</div>
	);
}
export function DateText({
	value,
	time = false,
}: {
	value?: string | null;
	time?: boolean;
}) {
	if (!value) return <span className="text-muted-foreground">—</span>;
	const date = new Date(value);
	return (
		<time dateTime={value} title={date.toLocaleString()}>
			{Number.isNaN(date.getTime())
				? "—"
				: date.toLocaleDateString(undefined, {
						month: "short",
						day: "numeric",
						year: "numeric",
						...(time ? { hour: "2-digit", minute: "2-digit" } : {}),
					})}
		</time>
	);
}
export function CopyValue({
	value,
	label = "Copy",
}: {
	value: string;
	label?: string;
}) {
	return (
		<button
			type="button"
			className="console-copy"
			aria-label={label}
			onClick={() => {
				void navigator.clipboard.writeText(value).then(
					() => toast.success("Copied"),
					() => toast.error("Could not copy. Select the text to copy it."),
				);
			}}
		>
			<Copy size={13} />
		</button>
	);
}
export function DetailPanel({
	title,
	onClose,
	children,
	wide = false,
}: {
	title: string;
	onClose: () => void;
	children: ReactNode;
	wide?: boolean;
}) {
	const panel = useRef<HTMLElement>(null);
	const close = useRef(onClose);
	close.current = onClose;
	const heading = useId();
	useEffect(() => {
		const previous = document.activeElement;
		const bodyOverflow = document.body.style.overflow;
		document.body.style.overflow = "hidden";
		panel.current?.querySelector<HTMLElement>("button")?.focus();
		return () => {
			document.body.style.overflow = bodyOverflow;
			if (previous instanceof HTMLElement) previous.focus();
		};
	}, []);
	return (
		<div className="console-panel-backdrop" onClick={onClose}>
			<section
				ref={panel}
				role="dialog"
				aria-modal="true"
				aria-labelledby={heading}
				className={`console-detail-panel ${wide ? "console-detail-wide" : ""}`}
				onClick={(event) => event.stopPropagation()}
				onKeyDown={(event) => {
					if (event.key === "Escape") {
						event.preventDefault();
						close.current();
					}
					if (event.key !== "Tab") return;
					const nodes = Array.from(
						panel.current?.querySelectorAll<HTMLElement>(
							'button:not([disabled]),a[href],input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex="0"]',
						) || [],
					).filter((node) => node.offsetParent !== null);
					const first = nodes[0];
					const last = nodes[nodes.length - 1];
					if (event.shiftKey && document.activeElement === first) {
						event.preventDefault();
						last?.focus();
					} else if (!event.shiftKey && document.activeElement === last) {
						event.preventDefault();
						first?.focus();
					}
				}}
			>
				<div className="console-panel-heading">
					<h2 id={heading}>{title}</h2>
					<Button
						type="button"
						variant="ghost"
						size="sm"
						onClick={onClose}
						aria-label={`Close ${title}`}
					>
						<X size={18} />
					</Button>
				</div>
				<div className="console-panel-content">{children}</div>
			</section>
		</div>
	);
}

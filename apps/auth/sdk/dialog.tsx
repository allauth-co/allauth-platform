"use client";

import { useEffect, useId, useRef, useState } from "react";
import type { CSSProperties, ReactNode } from "react";
import { createPortal } from "react-dom";
import { X } from "lucide-react";

let locks = 0;
let previousOverflow = "";
const focusable = 'a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),summary,[tabindex]:not([tabindex="-1"])';

function visibleControls(root: HTMLElement): HTMLElement[] {
	return [...root.querySelectorAll<HTMLElement>(focusable)].filter(element => {
		if (element.matches(":disabled") || Number(element.getAttribute("tabindex") ?? "0") < 0) return false;
		for (let ancestor: HTMLElement | null = element; ancestor && ancestor !== root; ancestor = ancestor.parentElement) {
			if (ancestor.hidden || ancestor.getAttribute("aria-hidden") === "true" || ancestor.hasAttribute("inert")) return false;
			if (ancestor.tagName === "DETAILS" && !ancestor.hasAttribute("open")) {
				const summary = [...ancestor.children].find(child => child.tagName === "SUMMARY");
				if (!summary?.contains(element)) return false;
			}
			const style = window.getComputedStyle(ancestor);
			if (style.display === "none" || style.visibility === "hidden" || style.visibility === "collapse") return false;
		}
		return true;
	});
}

/** Native SDK modal with an isolated portal, keyboard focus containment and focus restoration. */
export function Dialog({ open, onClose, title, children, sidebar, className = "", style, variant = "default" }: { open: boolean; onClose: () => void; title: string; children: ReactNode; sidebar?: ReactNode; className?: string; style?: CSSProperties; variant?: "default" | "account" }) {
	const titleId = useId();
	const panel = useRef<HTMLDivElement>(null);
	const close = useRef(onClose);
	close.current = onClose;
	const [mounted, setMounted] = useState(false);
	useEffect(() => { setMounted(true); }, []);
	useEffect(() => {
		if (!open || !mounted) return;
		const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
		if (locks++ === 0) { previousOverflow = document.body.style.overflow; document.body.style.overflow = "hidden"; }
		const timer = window.setTimeout(() => {
			const current = panel.current;
			if (!current || current.contains(document.activeElement)) return;
			(visibleControls(current)[0] ?? current).focus();
		}, 0);
		const keydown = (event: KeyboardEvent) => {
			if (event.key === "Escape") { event.preventDefault(); event.stopPropagation(); close.current(); return; }
			if (event.key !== "Tab" || !panel.current) return;
			const elements = visibleControls(panel.current);
			const first = elements[0]; const last = elements[elements.length - 1];
			if (!first) { event.preventDefault(); panel.current.focus(); return; }
			const activeIsVisible = elements.some(element => element === document.activeElement);
			if (event.shiftKey && (document.activeElement === first || !activeIsVisible)) { event.preventDefault(); last.focus(); }
			else if (!event.shiftKey && (document.activeElement === last || !activeIsVisible)) { event.preventDefault(); first.focus(); }
		};
		const keepFocus = (event: FocusEvent) => { if (panel.current && event.target instanceof Node && !panel.current.contains(event.target)) (visibleControls(panel.current)[0] ?? panel.current).focus(); };
		document.addEventListener("keydown", keydown, true); document.addEventListener("focusin", keepFocus);
		return () => { window.clearTimeout(timer); document.removeEventListener("keydown", keydown, true); document.removeEventListener("focusin", keepFocus); if (--locks === 0) document.body.style.overflow = previousOverflow; if (previous?.isConnected) previous.focus(); };
	}, [open, mounted]);
	if (!open || !mounted) return null;
	return createPortal(<div className={`allauth allauth-modal-backdrop${variant === "account" ? " allauth-account-dialog-backdrop" : ""} ${className}`} style={style} onMouseDown={event => { if (event.target === event.currentTarget) onClose(); }}>
		<div ref={panel} role="dialog" aria-modal="true" aria-labelledby={titleId} className={`allauth-modal${sidebar ? " allauth-modal-with-nav" : ""}`} tabIndex={-1}>
			{variant !== "account" && <header className="allauth-modal-header"><h2 id={titleId}>{title}</h2><button type="button" className="allauth-close" aria-label="Close dialog" onClick={onClose}>×</button></header>}
			<div className={`allauth-modal-layout${sidebar ? " allauth-modal-has-sidebar" : ""}`}>{sidebar && <aside className="allauth-modal-sidebar"><div className="allauth-modal-sidebar-content">{variant === "account" && <h2 id={titleId} className="allauth-account-dialog-title">{title}</h2>}{sidebar}</div></aside>}<div className="allauth-modal-main"><div className="allauth-modal-main-content">{children}</div></div></div>
			{variant === "account" && <button type="button" className="allauth-close allauth-account-dialog-close" aria-label="Close dialog" onClick={onClose}><X size={20} aria-hidden="true" /></button>}
		</div>
	</div>, document.body);
}

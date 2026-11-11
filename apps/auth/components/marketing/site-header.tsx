"use client";

import { ArrowRight, Menu, Moon, Sun, X } from "lucide-react";
import Link from "next/link";
import { useTheme } from "next-themes";
import { useRef, useState } from "react";
import { Logo } from "@/components/logo";

const navigation = [
	{ href: "/#product", label: "Product" },
	{ href: "/pricing", label: "Pricing" },
	{ href: "/compare", label: "Compare" },
	{ href: "/self-host", label: "Self-host" },
	{ href: "/sdk", label: "SDK" },
	{ href: "/releases", label: "Releases" },
] as const;

/** Public navigation with a persistent theme preference and a mobile menu. */
export function MarketingHeader() {
	const { resolvedTheme, setTheme } = useTheme();
	const [menuOpen, setMenuOpen] = useState(false);
	const menuButton = useRef<HTMLButtonElement>(null);
	return (
		<header className="homepage-header" onKeyDown={(event) => {
			if (event.key === "Escape" && menuOpen) {
				setMenuOpen(false);
				menuButton.current?.focus();
			}
		}}>
			<div className="homepage-container homepage-header-inner">
				<Link href="/" aria-label="AllAuth home" className="homepage-logo-link">
					<Logo className="homepage-logo" />
				</Link>
				<nav aria-label="Main navigation" className="homepage-desktop-nav">
					{navigation.map((item) => <a key={item.href} href={item.href}>{item.label}</a>)}
				</nav>
				<div className="homepage-header-actions">
					<button
						type="button"
						className="homepage-theme-button"
						aria-label="Toggle theme"
						title="Toggle light and dark theme"
						onClick={() => setTheme(resolvedTheme === "dark" ? "light" : "dark")}
					>
						<Sun className="homepage-sun" size={19} aria-hidden="true" />
						<Moon className="homepage-moon" size={19} aria-hidden="true" />
					</button>
					<Link href="/sign-in" className="homepage-sign-in" prefetch={false}>Sign in</Link>
					<Link href="/sign-up" className="homepage-button homepage-button-primary homepage-header-cta" prefetch={false}>
						Get started <ArrowRight size={16} aria-hidden="true" />
					</Link>
					<button
						type="button"
						ref={menuButton}
						className="homepage-menu-button"
						aria-label={menuOpen ? "Close navigation" : "Open navigation"}
						aria-expanded={menuOpen}
						aria-controls="homepage-mobile-navigation"
						onClick={() => setMenuOpen((open) => !open)}
					>
						{menuOpen ? <X size={21} aria-hidden="true" /> : <Menu size={21} aria-hidden="true" />}
					</button>
				</div>
			</div>
			{menuOpen && (
				<nav id="homepage-mobile-navigation" className="homepage-mobile-nav" aria-label="Mobile navigation">
					{navigation.map((item) => <a key={item.href} href={item.href} onClick={() => setMenuOpen(false)}>{item.label}</a>)}
					<Link href="/sign-in" prefetch={false}>Sign in</Link>
				</nav>
			)}
		</header>
	);
}

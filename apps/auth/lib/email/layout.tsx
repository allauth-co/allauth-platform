import { Body, Button, Container, Head, Heading, Hr, Html, Img, Link, Preview, Section, Text } from "@react-email/components";
import type { CSSProperties, ReactNode } from "react";
import type { ApplicationBranding } from "../branding/types";
import { emailBranding } from "./branding";

export const emailTextStyle: CSSProperties = { color: "#171923", fontSize: 15, lineHeight: "24px", margin: "0 0 20px", wordBreak: "break-word" };
export const emailMutedTextStyle: CSSProperties = { color: "#626775", fontSize: 12, lineHeight: "20px", margin: "0 0 12px", wordBreak: "break-word" };

/** A table-based, inline-styled layout shared by every transactional email. */
export function EmailLayout({ title, preview, branding, children, footer }: {
	title: string;
	preview?: string;
	branding?: ApplicationBranding | null;
	children: ReactNode;
	footer?: ReactNode;
}) {
	const brand = emailBranding(branding);
	return (
		<Html lang="en">
			<Head />
			<Preview>{preview || `${title} · ${brand.name}`}</Preview>
			<Body style={{ backgroundColor: "#f4f5f8", fontFamily: "Arial, Helvetica, sans-serif", margin: 0, padding: "32px 12px", color: "#171923" }}>
				<Container style={{ backgroundColor: "#ffffff", border: "1px solid #e5e7ee", borderTop: `4px solid ${brand.primaryColor}`, borderRadius: 12, margin: "0 auto", padding: "32px 28px", maxWidth: 520 }}>
					<Section style={{ marginBottom: 32 }}>
						{brand.logoUrl ? <Img src={brand.logoUrl} alt={brand.name} width="180" style={{ display: "block", maxWidth: 180, width: "auto", height: "auto", maxHeight: 80 }} /> : <Text style={{ ...emailTextStyle, fontSize: 22, fontWeight: 700, lineHeight: "28px", margin: 0 }}>{brand.name}</Text>}
					</Section>
					<Heading style={{ fontSize: 25, fontWeight: 700, lineHeight: "32px", margin: "0 0 24px", color: "#171923", wordBreak: "break-word" }}>{title}</Heading>
					{children}
					<Hr style={{ borderColor: "#e5e7ee", margin: "28px 0 20px" }} />
					{footer}
					{brand.supportEmail && <Text style={emailMutedTextStyle}>Need help? <Link href={`mailto:${brand.supportEmail}`} style={{ color: brand.linkColor, textDecoration: "underline" }}>{brand.supportEmail}</Link></Text>}
					<Text style={emailMutedTextStyle}>{brand.name} · Secure account access</Text>
					{brand.showPoweredBy && <Text style={{ ...emailMutedTextStyle, marginBottom: 0 }}>Powered by <Link href="https://allauth.co" style={{ color: "#626775", textDecoration: "underline" }}>AllAuth</Link></Text>}
				</Container>
			</Body>
		</Html>
	);
}

/** An accessible brand-colored action, with a visible URL fallback for mail clients. */
export function EmailAction({ url, label, branding }: { url: string; label: string; branding?: ApplicationBranding | null }) {
	const brand = emailBranding(branding);
	return <>
		<Section style={{ margin: "28px 0" }}><Button href={url} style={{ backgroundColor: brand.primaryColor, color: brand.foregroundColor, borderRadius: 7, padding: "14px 22px", fontSize: 15, fontWeight: 700, textDecoration: "none" }}>{label}</Button></Section>
		<Text style={emailMutedTextStyle}>You can also copy and paste this link into your browser:</Text>
		<Text style={{ ...emailMutedTextStyle, wordBreak: "break-all" }}><Link href={url} style={{ color: brand.linkColor, textDecoration: "underline" }}>{url}</Link></Text>
	</>;
}

/** Keep verification codes selectable, readable, and present in plain-text mail. */
export function EmailCode({ code }: { code: string }) {
	return <Text style={{ backgroundColor: "#f4f5f8", border: "1px solid #e5e7ee", borderRadius: 7, color: "#171923", fontFamily: "monospace", fontSize: 32, fontWeight: 700, letterSpacing: 6, lineHeight: "40px", margin: "24px 0", padding: "16px 12px", textAlign: "center" }}>{code}</Text>;
}

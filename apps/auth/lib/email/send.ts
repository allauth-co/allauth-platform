import { render } from "@react-email/components";
import type { ReactElement } from "react";

export interface EmailEnvironment {
	EMAIL_PROVIDER?: "cloudflare" | "resend";
	RESEND_API_KEY?: string;
	EMAIL?: {
		send(message: {
			from: string | { email: string; name: string };
			to: string;
			subject: string;
			html: string;
			text: string;
		}): Promise<unknown>;
	};
	EMAIL_FROM?: string;
	EMAIL_FROM_NAME?: string;
	CLOUDFLARE_ACCOUNT_ID?: string;
	CLOUDFLARE_EMAIL_API_TOKEN?: string;
}

export function emailConfigured(env: EmailEnvironment): boolean {
	if (env.EMAIL_PROVIDER === "resend") return Boolean(env.EMAIL_FROM && /^[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+$/.test(env.EMAIL_FROM) && /^re_[A-Za-z0-9_-]+$/.test(env.RESEND_API_KEY?.trim() || ""));
	return Boolean(env.EMAIL_FROM && (typeof env.EMAIL?.send === "function" || (/^[a-f0-9]{32}$/i.test(env.CLOUDFLARE_ACCOUNT_ID || "") && env.CLOUDFLARE_EMAIL_API_TOKEN?.trim())));
}

interface EmailSendResponse {
	success?: unknown;
	result?: { delivered?: unknown; queued?: unknown; permanent_bounces?: unknown; suppressed_recipients?: unknown };
}

/** Render once and use only the explicitly selected server-side transport. Provider acceptance is not inbox delivery. */
export async function sendAuthEmail(
	env: EmailEnvironment,
	message: { to: string; subject: string; react: ReactElement; fromName?: string },
) {
	if (!emailConfigured(env) || !env.EMAIL_FROM) {
		throw new Error(`${env.EMAIL_PROVIDER === "resend" ? "Resend" : "Cloudflare"} email delivery is not configured.`);
	}
	const [html, text] = await Promise.all([
		render(message.react),
		render(message.react, { plainText: true }),
	]);
	const payload = { from: env.EMAIL_FROM, to: message.to, subject: message.subject, html, text };
	const fromName = (message.fromName || env.EMAIL_FROM_NAME || "").replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, 100);
	if (env.EMAIL_PROVIDER === "resend") {
		const safeName = fromName.replace(/[<>"\\]/g, " ").trim();
		let response: Response;
		try {
			response = await fetch("https://api.resend.com/emails", {
				method: "POST", headers: { Authorization: `Bearer ${env.RESEND_API_KEY?.trim()}`, "Content-Type": "application/json" },
				body: JSON.stringify({ ...payload, from: safeName ? `${safeName} <${env.EMAIL_FROM}>` : env.EMAIL_FROM, to: [message.to] }),
				redirect: "error", signal: AbortSignal.timeout(10_000),
			});
		} catch { throw new Error("Resend email request failed."); }
		if (!response.ok) throw new Error(`Resend email delivery failed (HTTP ${response.status}).`);
		let result: unknown;
		try { result = await response.json(); } catch { throw new Error("Resend returned an invalid delivery response."); }
		if (!result || typeof result !== "object" || !("id" in result) || typeof result.id !== "string" || !result.id.trim()) throw new Error("Resend did not accept the email for delivery.");
		return;
	}
	if (typeof env.EMAIL?.send === "function") {
		try { await env.EMAIL.send({ ...payload, from: fromName ? { email: env.EMAIL_FROM, name: fromName } : env.EMAIL_FROM }); }
		catch { throw new Error("Cloudflare email delivery failed."); }
		return;
	}
	let response: Response;
	try {
		response = await fetch(`https://api.cloudflare.com/client/v4/accounts/${env.CLOUDFLARE_ACCOUNT_ID}/email/sending/send`, {
			method: "POST",
			headers: { Authorization: `Bearer ${env.CLOUDFLARE_EMAIL_API_TOKEN?.trim()}`, "Content-Type": "application/json" },
			body: JSON.stringify({ ...payload, from: fromName ? { address: env.EMAIL_FROM, name: fromName } : env.EMAIL_FROM }),
			redirect: "error",
			signal: AbortSignal.timeout(10_000),
		});
	} catch { throw new Error("Cloudflare email request failed."); }
	if (!response.ok) throw new Error(`Cloudflare email delivery failed (HTTP ${response.status}).`);
	let body: EmailSendResponse;
	try { body = await response.json() as EmailSendResponse; }
	catch { throw new Error("Cloudflare email returned an invalid delivery response."); }
	const recipient = message.to.toLowerCase();
	const includesRecipient = (value: unknown) => Array.isArray(value) && value.some((item) => typeof item === "string" && item.toLowerCase() === recipient);
	if (body?.success !== true || includesRecipient(body.result?.permanent_bounces) || includesRecipient(body.result?.suppressed_recipients) || !(includesRecipient(body.result?.delivered) || includesRecipient(body.result?.queued))) {
		throw new Error("Cloudflare did not accept the email for delivery.");
	}
}

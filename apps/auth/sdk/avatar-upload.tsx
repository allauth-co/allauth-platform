"use client";

import { useId, useRef, useState } from "react";
import { useAllAuth } from "./react";
import { Avatar } from "./header";
import { authError, proxyBasePath } from "./helpers";

type ImageContentType = "image/png" | "image/jpeg" | "image/webp";
export type NormalizedProfileImage = { contentType: ImageContentType; data: string };
const formats = new Set<string>(["image/png", "image/jpeg", "image/webp"]);
const sourceLimit = 5 * 1024 * 1024;
const encodedLimit = 128 * 1024;

async function decode(file: File): Promise<{ source: CanvasImageSource; width: number; height: number; release: () => void }> {
	if (typeof createImageBitmap === "function") {
		const image = await createImageBitmap(file);
		return { source: image, width: image.width, height: image.height, release: () => image.close() };
	}
	const url = URL.createObjectURL(file);
	const image = new Image();
	try {
		await new Promise<void>((resolve, reject) => { image.onload = () => resolve(); image.onerror = () => reject(new Error("This photo could not be opened. Choose another image.")); image.src = url; });
		return { source: image, width: image.naturalWidth, height: image.naturalHeight, release: () => URL.revokeObjectURL(url) };
	} catch (cause) { URL.revokeObjectURL(url); throw cause; }
}

/** Resize and re-encode in the browser before sending a small image through the signed SDK proxy. */
export async function normalizeProfileImage(file: File): Promise<NormalizedProfileImage> {
	if (!formats.has(file.type)) throw new Error("Choose a PNG, JPG or WebP photo.");
	if (file.size === 0) throw new Error("Choose a photo that is not empty.");
	if (file.size > sourceLimit) throw new Error("Choose a photo no larger than 5 MB.");
	const image = await decode(file);
	try {
		if (!Number.isFinite(image.width) || !Number.isFinite(image.height) || image.width <= 0 || image.height <= 0) throw new Error("This photo has invalid dimensions.");
		const canvas = document.createElement("canvas");
		const context = canvas.getContext("2d");
		if (!context) throw new Error("Your browser could not prepare this photo.");
		for (const edge of [512, 384, 288, 216, 162, 122]) {
			const ratio = Math.min(1, edge / Math.max(image.width, image.height));
			canvas.width = Math.max(1, Math.round(image.width * ratio));
			canvas.height = Math.max(1, Math.round(image.height * ratio));
			context.drawImage(image.source, 0, 0, canvas.width, canvas.height);
			for (const quality of [.86, .72, .58, .42]) {
				const blob = await new Promise<Blob>((resolve, reject) => canvas.toBlob((result) => result ? resolve(result) : reject(new Error("Your browser could not prepare this photo.")), "image/webp", quality));
				if (!formats.has(blob.type)) throw new Error("Your browser could not prepare a supported photo.");
				if (blob.size === 0 || blob.size > encodedLimit) continue;
				const bytes = new Uint8Array(await blob.arrayBuffer());
				let binary = "";
				for (let index = 0; index < bytes.length; index += 0x8000) binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
				return { contentType: blob.type as ImageContentType, data: btoa(binary) };
			}
		}
		throw new Error("This photo could not be made small enough. Choose another image.");
	} finally { image.release(); }
}

/** Store an image draft. Saving the native profile applies its returned URL to the account. */
export async function uploadProfileImage(basePath: string, image: NormalizedProfileImage): Promise<string> {
	const response = await fetch(`${proxyBasePath(basePath)}/sdk/avatar`, { method: "POST", credentials: "same-origin", cache: "no-store", headers: { "Content-Type": "application/json" }, body: JSON.stringify(image) });
	const value: unknown = await response.json();
	const record = value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
	if (!response.ok) throw new Error(typeof record?.message === "string" ? record.message : typeof record?.error === "string" ? record.error : "Your photo could not be uploaded. Please try again.");
	try {
		if (typeof record?.url !== "string") throw new Error();
		const url = new URL(record.url);
		if (url.protocol !== "https:" || url.username || url.password) throw new Error();
		return url.href;
	} catch { throw new Error("The photo service returned an invalid image URL."); }
}

/** Shared controlled photo picker used by both account pages and account dialogs. */
export function AvatarUpload({ name, image, onChange, disabled = false, onBusyChange }: {
	name: string; image?: string | null; onChange: (image: string | null) => void; disabled?: boolean; onBusyChange?: (busy: boolean) => void;
}) {
	const { basePath, capabilities } = useAllAuth();
	const input = useRef<HTMLInputElement>(null);
	const id = useId();
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState("");
	const [message, setMessage] = useState("");
	async function upload(file: File) {
		if (busy || disabled || !capabilities?.profileImageUpload) return;
		setBusy(true); onBusyChange?.(true); setError(""); setMessage("");
		try { const value = await uploadProfileImage(basePath, await normalizeProfileImage(file)); onChange(value); setMessage("Photo ready. Save your profile to apply it."); }
		catch (cause) { setError(authError(cause)); }
		finally { setBusy(false); onBusyChange?.(false); }
	}
	return <div className="allauth-avatar-upload">
		<Avatar name={name} image={image}/><div><p className="allauth-avatar-upload-label">Profile photo</p><div className="allauth-avatar-upload-actions">
			{capabilities?.profileImageUpload && <><input ref={input} id={id} type="file" accept="image/png,image/jpeg,image/webp" aria-label="Upload profile photo" hidden disabled={disabled || busy} onChange={(event) => { const file = event.currentTarget.files?.[0]; event.currentTarget.value = ""; if (file) void upload(file); }}/><button type="button" className="allauth-secondary allauth-compact-button" disabled={disabled || busy} onClick={() => input.current?.click()}>{busy ? "Uploading…" : "Upload photo"}</button></>}
			{image && <button type="button" className="allauth-text-button" disabled={disabled || busy} onClick={() => { onChange(null); setError(""); setMessage("Photo removed. Save your profile to apply it."); }}>Remove photo</button>}
		</div><p className="allauth-muted">{capabilities?.profileImageUpload ? "PNG, JPG or WebP, up to 5 MB." : "Photo upload is not available for this app."}</p>{error && <p className="allauth-notice allauth-error" role="alert">{error}</p>}{message && <p className="allauth-muted" role="status">{message}</p>}</div>
	</div>;
}

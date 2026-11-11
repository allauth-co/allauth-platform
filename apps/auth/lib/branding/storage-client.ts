import { randomUUID } from "node:crypto";
import { APIError } from "better-auth";
import type { AuthEnvironment } from "../configuration";
import { setting } from "../configuration";
import { signAssetHeaders } from "./asset-signature";
import type { ValidatedBrandingAsset } from "./types";
import { brandingAssetOrigin, brandingStorage } from "./validation";

/** Upload immutable, validated image bytes through the narrowly signed Cloudflare asset Worker. */
export async function storeBrandingAsset(asset: ValidatedBrandingAsset, scope: { workspaceId: string; applicationId: string }, env: AuthEnvironment): Promise<string> {
	if (!brandingStorage(env).available) throw new APIError("SERVICE_UNAVAILABLE", { message: "Brand asset storage is not configured." });
	const url = `${brandingAssetOrigin(env)}/branding/${scope.workspaceId}/${scope.applicationId}/${randomUUID()}.${asset.extension}`;
	const request = new Request(url, { method: "PUT", headers: { "content-type": asset.contentType }, body: asset.bytes });
	try {
		const headers = await signAssetHeaders(request, setting(env, "ALLAUTH_ASSET_SECRET"));
		const response = await fetch(url, { method: "PUT", headers, body: asset.bytes, redirect: "error", cache: "no-store", signal: AbortSignal.timeout(15000) });
		if (response.status !== 201) throw new Error("Asset upload failed.");
		const payload: unknown = await response.json();
		if (!payload || typeof payload !== "object" || !("url" in payload) || payload.url !== url) throw new Error("Invalid asset upload response.");
		return url;
	} catch { throw new APIError("SERVICE_UNAVAILABLE", { message: "The brand asset could not be uploaded. Try again." }); }
}

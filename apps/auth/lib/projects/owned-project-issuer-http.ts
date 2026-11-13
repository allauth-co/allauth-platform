import { createHash } from "node:crypto";

export const maximumIssuerFormBytes = 24 * 1024;
const noStore = { "cache-control": "no-store", pragma: "no-cache" };

export class ProjectOAuthError extends Error {
	constructor(
		readonly code: string,
		message: string,
		readonly status = 400,
		readonly challenge?: string,
	) {
		super(message);
	}

	response() {
		const headers = new Headers(noStore);
		if (this.challenge) headers.set("www-authenticate", this.challenge);
		return Response.json(
			{ error: this.code, error_description: this.message },
			{ status: this.status, headers },
		);
	}
}

export function issuerJSON(body: object, status = 200) {
	return Response.json(body, { status, headers: noStore });
}

export function issuerDigest(value: string) {
	return createHash("sha256").update(value).digest("base64url");
}

export async function issuerForm(request: Request) {
	const contentType = request.headers
		.get("content-type")
		?.split(";")[0]
		?.trim()
		.toLowerCase();
	if (
		contentType !== "application/x-www-form-urlencoded" ||
		Number(request.headers.get("content-length")) > maximumIssuerFormBytes
	) {
		throw new ProjectOAuthError(
			"invalid_request",
			"Supply a form-encoded OAuth request.",
		);
	}
	const reader = request.body?.getReader();
	const decoder = new TextDecoder("utf-8", { fatal: true });
	let body = "";
	let bytes = 0;
	if (reader) {
		try {
			for (;;) {
				const part = await reader.read();
				if (part.done) break;
				bytes += part.value.byteLength;
				if (bytes > maximumIssuerFormBytes) {
					void reader.cancel().catch(() => {});
					throw new ProjectOAuthError(
						"invalid_request",
						"The OAuth request is too large.",
					);
				}
				body += decoder.decode(part.value, { stream: true });
			}
			body += decoder.decode();
		} catch (error) {
			if (error instanceof ProjectOAuthError) throw error;
			throw new ProjectOAuthError(
				"invalid_request",
				"The OAuth request is malformed.",
			);
		} finally {
			reader.releaseLock();
		}
	}
	return issuerFormParameters(new URLSearchParams(body));
}

/** Recheck a bounded, already-decoded form without consuming its request again. */
export function issuerFormParameters(form: URLSearchParams) {
	const fields = new Set<string>();
	for (const [name] of form) {
		if (name !== "resource" && fields.has(name))
			throw new ProjectOAuthError(
				"invalid_request",
				"OAuth parameters must occur once.",
			);
		fields.add(name);
	}
	return form;
}

const sharedOtpBodies = new WeakMap<Request, Promise<unknown>>();

/** Inspect the shared send route once, leaving the original request body intact. */
export function readSharedProjectEmailOtpBody(request: Request) {
	const cached = sharedOtpBodies.get(request);
	if (cached) return cached;
	const result = readProjectEmailProofBody(request.clone());
	sharedOtpBodies.set(request, result);
	return result;
}

/** Read bounded JSON or form proof fields without collapsing duplicates. */
export async function readProjectEmailProofBody(
	request: Pick<Request, "headers" | "body">,
): Promise<unknown> {
	const mime = request.headers
		.get("content-type")
		?.split(";", 1)[0]
		?.trim()
		.toLowerCase();
	const form = mime === "application/x-www-form-urlencoded";
	if (!form && mime !== "application/json") return undefined;
	const reader = request.body?.getReader();
	if (!reader) return undefined;
	const decoder = new TextDecoder("utf-8", { fatal: true });
	let length = 0;
	let content = "";
	let expired = false;
	const deadline = setTimeout(() => {
		expired = true;
		void reader.cancel().catch(() => {});
	}, 5_000);
	try {
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;
			length += value.byteLength;
			if (length > 8192) {
				void reader.cancel().catch(() => {});
				return undefined;
			}
			content += decoder.decode(value, { stream: true });
		}
		if (expired) return undefined;
		content += decoder.decode();
		if (!form) return JSON.parse(content);
		const fields = new URLSearchParams(content);
		if (new Set(fields.keys()).size !== fields.size) return undefined;
		return Object.fromEntries(fields);
	} catch {
		void reader.cancel().catch(() => {});
		return undefined;
	} finally {
		clearTimeout(deadline);
		reader.releaseLock();
	}
}

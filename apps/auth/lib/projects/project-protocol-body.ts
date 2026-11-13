const bodyDeadlineMs = 5000;
const scimBodyBytes = 262_144;
const samlFormBytes = 3 * 256 * 1024 + 4096;

export type ProjectProtocolBody = "scim" | "saml";

/** Only the SCIM mutation and SAML ACS transports need this ingress deadline. */
export function projectProtocolBody(
	request: Request,
	basePath: string,
): ProjectProtocolBody | null {
	const pathname = new URL(request.url).pathname;
	if (!pathname.startsWith(`${basePath}/`)) return null;
	const path = pathname.slice(basePath.length);
	if (
		["POST", "PUT", "PATCH"].includes(request.method) &&
		path.startsWith("/scim/v2/")
	)
		return "scim";
	if (request.method === "POST" && /^\/sso\/saml2\/sp\/acs\/[^/]+$/.test(path))
		return "saml";
	return null;
}

/** Keep one deadline across pre-admission, replay and cancellation of the same byte stream. */
export function timedProjectProtocolStream(source: ReadableStream<Uint8Array>) {
	const reader = source.getReader();
	let timer: ReturnType<typeof setTimeout>;
	let active = true;
	let expired = false;

	function finish() {
		if (!active) return false;
		active = false;
		clearTimeout(timer);
		return true;
	}

	function cancel(reason: unknown) {
		void reader.cancel(reason).catch(() => undefined);
		reader.releaseLock();
	}

	const stream = new ReadableStream<Uint8Array>({
		start(controller) {
			timer = setTimeout(() => {
				if (!finish()) return;
				expired = true;
				const error = new Error("The project protocol request body timed out.");
				controller.error(error);
				cancel(error);
			}, bodyDeadlineMs);
		},
		async pull(controller) {
			try {
				const item = await reader.read();
				if (!active) return;
				if (item.done) {
					finish();
					reader.releaseLock();
					controller.close();
				} else {
					controller.enqueue(item.value);
				}
			} catch (error) {
				if (!finish()) return;
				reader.releaseLock();
				controller.error(error);
			}
		},
		cancel(reason) {
			if (finish()) cancel(reason);
		},
	});
	return { stream, timedOut: () => expired };
}

/** Replay the original bytes and media type without imposing an owned limit on the legacy parser. */
export async function prepareProjectProtocolBody(
	request: Request,
	protocol: ProjectProtocolBody,
) {
	const body = request.body;
	const media = request.headers
		.get("content-type")
		?.split(";", 1)[0]
		?.trim()
		.toLowerCase();
	if (
		!body ||
		(media !== "application/json" &&
			media !==
				(protocol === "scim"
					? "application/scim+json"
					: "application/x-www-form-urlencoded"))
	)
		return null;
	const timed = timedProjectProtocolStream(body);
	const [preflight, forwarding] = timed.stream.tee();
	const reader = preflight.getReader();
	const limit = protocol === "scim" ? scimBodyBytes : samlFormBytes;
	let size = 0;
	try {
		while (size <= limit) {
			const item = await reader.read();
			if (item.done) break;
			size += item.value.byteLength;
		}
	} catch {
		// The forwarding branch exposes the same read failure to the selected parser.
	} finally {
		// A tee cancellation can wait on its other branch. Release the preflight
		// without waiting so the legacy parser can still read larger valid requests.
		void reader.cancel().catch(() => undefined);
		reader.releaseLock();
	}
	return {
		request: new Request(request, {
			body: forwarding,
			duplex: "half",
		} as RequestInit),
		timedOut: timed.timedOut,
	};
}

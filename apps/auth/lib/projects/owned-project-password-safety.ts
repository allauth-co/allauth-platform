import { createHash } from "node:crypto";

const maximumRangeBytes = 512 * 1024;
const rangeLine = /^([0-9A-F]{35}):(0|[1-9][0-9]*)$/i;

async function readRange(response: Response) {
	const reader = response.body?.getReader();
	if (!reader) throw new Error("Password range is unavailable.");
	const decoder = new TextDecoder("utf-8", { fatal: true });
	let result = "";
	let size = 0;
	try {
		while (true) {
			const chunk = await reader.read();
			if (chunk.done) break;
			size += chunk.value.byteLength;
			if (size > maximumRangeBytes) {
				void reader.cancel().catch(() => undefined);
				throw new Error("Password range is too large.");
			}
			result += decoder.decode(chunk.value, { stream: true });
		}
		return result + decoder.decode();
	} finally {
		reader.releaseLock();
	}
}

/** Use the existing breach corpus and send only the padded SHA-1 range prefix. */
export function createOwnedProjectPasswordSafety(
	fetchRange = (request: Request) => fetch(request),
) {
	return async function checkPasswordSafety(
		password: string,
	): Promise<"allowed" | "breached" | "unavailable"> {
		const digest = createHash("sha1")
			.update(password)
			.digest("hex")
			.toUpperCase();
		try {
			const response = await fetchRange(
				new Request(
					`https://api.pwnedpasswords.com/range/${digest.slice(0, 5)}`,
					{
						headers: {
							"Add-Padding": "true",
							"User-Agent": "AllAuth Password Checker",
						},
						redirect: "error",
						signal: AbortSignal.timeout(5_000),
					},
				),
			);
			if (!response.ok) return "unavailable";
			const body = (await readRange(response)).trimEnd();
			let breached = false;
			for (const line of body.split(/\r?\n/)) {
				const match = rangeLine.exec(line);
				if (!match || !Number.isSafeInteger(Number(match[2])))
					return "unavailable";
				if (match[1]!.toUpperCase() === digest.slice(5) && Number(match[2]) > 0)
					breached = true;
			}
			return breached ? "breached" : "allowed";
		} catch {
			return "unavailable";
		}
	};
}

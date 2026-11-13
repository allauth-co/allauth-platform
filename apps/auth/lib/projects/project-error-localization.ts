import type { AuthEngine } from "../auth-engine";
import messages from "./legacy-auth-error-messages.json";

const catalog: Record<string, Readonly<Record<string, string>>> = messages;
const beforeHookErrors = new WeakSet<Response>();

/** Preserve an error that the native pre-handler returns before localization. */
export function preserveProjectBeforeHookError(response: Response) {
	beforeHookErrors.add(response);
	return response;
}

/** Preserve the existing header-only negotiation and English default. */
function preferredLocale(acceptLanguage: string | null) {
	const ranges = (acceptLanguage ?? "").split(",").map((range) => {
		const [tag, quality = "q=1"] = range.trim().split(";");
		return {
			locale: tag?.trim().split("-")[0] ?? "",
			quality: Number.parseFloat(quality.replace("q=", "")),
		};
	});
	ranges.sort((left, right) => right.quality - left.quality);
	return (
		ranges.find(({ locale }) => Object.hasOwn(catalog, locale))?.locale ?? "en"
	);
}

async function localizeError(request: Request, response: Response) {
	if (
		beforeHookErrors.has(response) ||
		response.status < 400 ||
		!response.headers.get("content-type")?.includes("application/json")
	)
		return response;
	const value: unknown = await response
		.clone()
		.json()
		.catch(() => null);
	if (
		!value ||
		typeof value !== "object" ||
		!("code" in value) ||
		typeof value.code !== "string" ||
		!("message" in value) ||
		typeof value.message !== "string"
	)
		return response;
	const localized =
		catalog[preferredLocale(request.headers.get("accept-language"))];
	if (!localized || !Object.hasOwn(localized, value.code)) return response;
	const headers = new Headers(response.headers);
	headers.delete("content-length");
	return Response.json(
		{
			...value,
			message: localized[value.code],
			originalMessage: value.message,
		},
		{
			status: response.status,
			statusText: response.statusText,
			headers,
		},
	);
}

export function localizeProjectErrors(engine: AuthEngine): AuthEngine {
	return {
		...engine,
		async dispatch(request) {
			return localizeError(request, await engine.dispatch(request));
		},
		async readSession(request) {
			return localizeError(request, await engine.readSession(request));
		},
	};
}

import { APIError } from "better-auth";
import { json } from "@/lib/api";
import { withPortalAuthEngine } from "@/lib/domains/hosting";

export async function GET(request: Request) {
	try {
		return await withPortalAuthEngine(request, (engine, _env, bound) =>
			engine.readOAuthContext(bound),
		);
	} catch (error) {
		if (error instanceof APIError)
			return json(
				{ error: error.body?.message || "The request is not permitted." },
				error.statusCode,
			);
		console.error(
			"AllAuth OAuth context failed",
			error instanceof Error ? error.name : "UnknownError",
		);
		return json({ error: "The request could not be completed." }, 500);
	}
}

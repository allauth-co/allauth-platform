import { hostedPresentation } from "@/lib/domains/hosted-organization-preview";
import { isProjectWriterUnavailable } from "@/lib/projects/project-engine-unavailable";

function presentationResponse(body: object, status: number) {
	return Response.json(body, {
		status,
		headers: { "Cache-Control": "no-store" },
	});
}

export async function GET(request: Request) {
	try {
		const mode = await hostedPresentation(request.headers);
		if (mode) return presentationResponse({ mode }, 200);
		return presentationResponse(
			{ error: "Authentication hostname is not active." },
			404,
		);
	} catch (error) {
		if (!isProjectWriterUnavailable(error)) throw error;
		return presentationResponse(
			{ error: "Project authentication is temporarily unavailable." },
			503,
		);
	}
}

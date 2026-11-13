import * as z from "zod";
import {
	ownedSCIMError,
	ownedSCIMResponse,
} from "./owned-project-scim-discovery";

const patch = z.object({
	schemas: z
		.array(z.literal("urn:ietf:params:scim:api:messages:2.0:PatchOp"))
		.length(1, "schemas must contain only the PatchOp schema"),
	Operations: z.array(
		z.object({
			op: z
				.string()
				.toLowerCase()
				.default("replace")
				.pipe(z.enum(["replace", "add", "remove"])),
			path: z.string().optional(),
			value: z.unknown().optional(),
		}),
	),
});

export function ownedSCIMBodyValidation(issues: readonly z.core.$ZodIssue[]) {
	return issues
		.map(
			(issue) =>
				`[body${issue.path.length ? `.${issue.path.join(".")}` : ""}] ${issue.message}`,
		)
		.join("; ");
}

export function parseOwnedSCIMPatch(input: unknown) {
	const result = patch.safeParse(input);
	if (!result.success)
		throw ownedSCIMError(
			400,
			ownedSCIMBodyValidation(result.error.issues),
			"invalidValue",
		);
	return result.data.Operations;
}

export async function readOwnedSCIMBody(
	request: Request,
	resource: "User" | "Group",
): Promise<unknown> {
	const media = request.headers
		.get("content-type")
		?.split(";", 1)[0]
		?.trim()
		.toLowerCase();
	if (media !== "application/scim+json" && media !== "application/json")
		throw ownedSCIMError(
			415,
			"SCIM requests must use application/scim+json or application/json",
		);
	const reader = request.body?.getReader();
	const decoder = new TextDecoder();
	let size = 0;
	let body = "";
	if (reader) {
		try {
			while (true) {
				const chunk = await reader.read();
				if (chunk.done) break;
				size += chunk.value.byteLength;
				if (size > 262_144) {
					await reader.cancel().catch(() => undefined);
					throw ownedSCIMError(
						413,
						`SCIM ${resource} request exceeds the supported size`,
					);
				}
				body += decoder.decode(chunk.value, { stream: true });
			}
			body += decoder.decode();
		} finally {
			reader.releaseLock();
		}
	}
	try {
		return JSON.parse(body);
	} catch {
		throw ownedSCIMError(
			400,
			"SCIM request body must contain valid JSON",
			"invalidSyntax",
		);
	}
}

export function ownedSCIMDatabaseCode(error: unknown) {
	return error && typeof error === "object" && "code" in error
		? error.code
		: undefined;
}

/** Retries only database transactions that could not commit. */
export async function retryOwnedSCIMMutation(
	resource: "User" | "Group",
	mutate: () => Promise<Response>,
): Promise<Response> {
	for (let attempt = 1; attempt <= 3; attempt++) {
		try {
			return await mutate();
		} catch (error) {
			const code = ownedSCIMDatabaseCode(error);
			if (code !== "40001" && code !== "40P01") throw error;
		}
	}
	return ownedSCIMError(
		409,
		`The SCIM ${resource} changed concurrently; retry the request`,
	);
}

export function ownedSCIMMutationResponse(
	body: object,
	location: string,
	created: boolean,
) {
	const response = ownedSCIMResponse(body, created ? 201 : 200);
	response.headers.set("Location", location);
	if (created) response.headers.set("Content-Location", location);
	return response;
}

export function ownedSCIMMutationNoContent() {
	return new Response(null, {
		status: 204,
		headers: {
			"Content-Type": "application/scim+json",
			"Cache-Control": "no-store",
			Pragma: "no-cache",
		},
	});
}

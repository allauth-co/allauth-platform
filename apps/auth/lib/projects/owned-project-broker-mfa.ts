import * as z from "zod";

export const projectBrokerTwoFactorBody = z
	.object({
		code: z.string().trim().min(1).max(128),
		method: z.enum(["totp", "backup"]),
	})
	.strict();

export type ProjectBrokerFactor = z.infer<typeof projectBrokerTwoFactorBody>;

/** Bind a verified transport to the broker client on the same live project registry row. */
export type AuthorizeProjectBrokerMfa = (request: Request) => Promise<{
	request: Request;
	verify(factor: ProjectBrokerFactor): Promise<Response>;
} | null>;

interface BrokerMfaOptions {
	authorize: AuthorizeProjectBrokerMfa;
	admit(request: Request): Promise<Response | null>;
	readBody(request: Request): Promise<unknown>;
}

function failure(status: number, code: string, message: string) {
	return Response.json(
		{ code, message },
		{
			status,
			headers: {
				"Cache-Control": "no-store",
				Pragma: "no-cache",
				"Referrer-Policy": "no-referrer",
			},
		},
	);
}

const forbidden = () => failure(403, "FORBIDDEN", "Invalid app proxy request.");

/** Relay a signed application factor check to the shared broker's authoritative MFA handler. */
export async function verifyOwnedProjectBrokerMfa(
	request: Request,
	options: BrokerMfaOptions,
): Promise<Response> {
	const origin = request.headers.get("allauth-proxy-origin");
	if (
		request.method !== "POST" ||
		!request.headers.get("allauth-proxy-signature") ||
		!origin ||
		request.headers.get("origin") !== origin ||
		request.headers.has("authorization") ||
		request.headers.get("sec-fetch-site") === "cross-site"
	)
		return forbidden();

	const proof = await options.authorize(request);
	if (!proof) return forbidden();
	const refusal = await options.admit(proof.request);
	if (refusal) return refusal;
	const factor = projectBrokerTwoFactorBody.safeParse(
		await options.readBody(proof.request.clone() as Request),
	);
	if (!factor.success)
		return failure(
			400,
			"VALIDATION_ERROR",
			"Supply a verification code and method.",
		);
	return proof.verify(factor.data);
}

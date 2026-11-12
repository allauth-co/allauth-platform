import { APIError } from "better-auth";
import { runWithAdapter } from "@better-auth/core/context";
import type { AuthInstance } from "../api";
import { verifyBrokerTwoFactor } from "../broker-two-factor";
import type { ProjectBrokerFactor } from "./owned-project-broker-mfa";
import { projectBrokerTwoFactorBody } from "./owned-project-broker-mfa";
import type { Project } from "./registry";

export { projectBrokerTwoFactorBody } from "./owned-project-broker-mfa";

/** Invoked with the current registry row after verifiedProjectRequest has authenticated the signed transport. */
export async function projectBrokerTwoFactor(
	request: Request,
	project: Project,
	platform: AuthInstance,
	platformOrigin: string,
	parsedBody?: ProjectBrokerFactor,
): Promise<Response> {
	const origin = request.headers.get("allauth-proxy-origin");
	if (
		request.method !== "POST" ||
		!request.headers.get("allauth-proxy-signature") ||
		!origin ||
		!project.origins.includes(origin) ||
		request.headers.get("origin") !== origin
	)
		throw new APIError("FORBIDDEN");
	const prefix = `allauth_project_${project.slug}.`;
	const cookies = (request.headers.get("cookie") || "")
		.split(";")
		.map((value) => value.trim());
	const read = (name: string) => {
		const found = cookies.filter(
			(pair) =>
				pair.split("=", 1)[0]?.replace(/^__Secure-/, "") === `${prefix}${name}`,
		);
		if (found.length !== 1)
			throw new APIError("UNAUTHORIZED", {
				message: "This sign-in has expired. Start again.",
			});
		return found[0]!.slice(found[0]!.indexOf("=") + 1);
	};
	const body = projectBrokerTwoFactorBody.parse(
		parsedBody ?? (await request.json()),
	);
	// A project endpoint runs inside its own adapter context. Never let that
	// ambient context select the application DB for central challenge records.
	const result = await runWithAdapter((await platform.$context).adapter, () =>
		verifyBrokerTwoFactor(
			platform,
			platformOrigin,
			{ clientId: project.brokerClientId, slug: project.slug, origin },
			{
				...body,
				ticket: read("broker_mfa_ticket"),
				binding: read("broker_mfa_binding"),
			},
			request.headers,
		),
	);
	return Response.json(result, {
		headers: { "cache-control": "no-store", "referrer-policy": "no-referrer" },
	});
}

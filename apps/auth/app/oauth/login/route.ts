import { APIError } from "better-auth";
import { apiRoute } from "@/lib/api";
import { brokerLogin } from "@/lib/broker-login";
import { withPortalAuthEngine } from "@/lib/domains/hosting";

/** The central broker chooses only a native provider from a verified authorization request. */
export const GET = (request: Request) =>
	apiRoute(
		request,
		async (instance) =>
			withPortalAuthEngine(request, async (_engine, env, bound, binding) => {
				if (binding)
					throw new APIError("BAD_REQUEST", {
						message: "Use the platform identity connection for this request.",
					});
				return brokerLogin(bound, instance, env);
			}),
		{ platformOnly: true },
	);

import { apiRoute } from "@/lib/api";
import { dispatchPlatformAuth } from "@/lib/auth";
import { completeBrokerTwoFactor } from "@/lib/broker-two-factor";
import { withPlatformIssuerRuntime } from "@/lib/platform-issuer-runtime";

export async function GET(request: Request) {
	const response = await apiRoute(
		request,
		(instance, env) =>
			withPlatformIssuerRuntime(env, ({ candidate }) =>
				candidate
					? candidate.brokerMfa.complete(request)
					: completeBrokerTwoFactor(instance, request, (input) =>
							dispatchPlatformAuth(input, instance, env),
						),
			),
		{ platformOnly: true },
	);
	response.headers.set("Referrer-Policy", "no-referrer");
	return response;
}

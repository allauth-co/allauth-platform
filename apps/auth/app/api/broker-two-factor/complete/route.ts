import { apiRoute } from "@/lib/api";
import { dispatchPlatformAuth } from "@/lib/auth";
import { completeBrokerTwoFactor } from "@/lib/broker-two-factor";

export async function GET(request: Request) {
	const response = await apiRoute(
		request,
		(instance, env) =>
			completeBrokerTwoFactor(instance, request, (input) =>
				dispatchPlatformAuth(input, instance, env),
			),
		{ platformOnly: true },
	);
	response.headers.set("Referrer-Policy", "no-referrer");
	return response;
}

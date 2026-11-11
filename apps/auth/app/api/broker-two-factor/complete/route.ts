import { apiRoute } from "@/lib/api";
import { completeBrokerTwoFactor } from "@/lib/broker-two-factor";

export async function GET(request: Request) {
	const response = await apiRoute(
		request,
		(instance) => completeBrokerTwoFactor(instance, request),
		{ platformOnly: true },
	);
	response.headers.set("Referrer-Policy", "no-referrer");
	return response;
}

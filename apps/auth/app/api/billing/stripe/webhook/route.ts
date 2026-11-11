import { APIError } from "better-auth";
import { json } from "@/lib/api";
import { getAuthEnvironment } from "@/lib/auth";
import { receiveStripeWebhook } from "@/lib/billing/webhook";

export async function POST(request: Request) {
	try { return json(await receiveStripeWebhook(request, await getAuthEnvironment())); }
	catch (error) {
		if (error instanceof APIError) return json({ error: error.body?.message ?? "The webhook could not be accepted." }, error.statusCode);
		return json({ error: "The webhook could not be accepted. Retry this delivery." }, 503);
	}
}

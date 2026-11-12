import { createHmac } from "node:crypto";
import type { AuthEnvironment } from "../configuration";
import { setting } from "../configuration";

/** Distinct keys isolate signed cookies, encrypted credentials, and security counters. */
export function projectSecret(env: AuthEnvironment, projectId: string): string {
	return createHmac("sha256", setting(env, "ALLAUTH_AUTH_SECRET"))
		.update(`allauth:project:${projectId}`)
		.digest("hex");
}

import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { portalSession } from "@/lib/domains/hosting";
import { OAuthConsent } from "@/components/oauth-consent";
export default async function Page({
	searchParams,
}: {
	searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
	const session = await portalSession(await headers());
	if (!session) {
		const params = await searchParams;
		const query = new URLSearchParams();
		for (const [key, value] of Object.entries(params)) {
			if (typeof value === "string") query.append(key, value);
			else if (Array.isArray(value))
				for (const part of value) query.append(key, part);
		}
		redirect(`/sign-in?${query}`);
	}
	return <OAuthConsent name={session.user.name} email={session.user.email} />;
}

import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { portalSession } from "@/lib/domains/hosting";
import { OrganizationManager } from "@/components/organization-manager";
export default async function Page() {
	const session = await portalSession(await headers());
	if (!session) redirect("/sign-in?callbackUrl=%2Forganizations");
	return <OrganizationManager />;
}

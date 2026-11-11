import { notFound } from "next/navigation";
import { AllAuthAuth } from "@/components/better-auth-ui/allauth-auth";
const paths = new Set([
	"enterprise-sign-in",
	"reset-link-sent",
	"magic-link",
	"magic-link-sent",
	"email-otp",
	"sign-out",
	"auth-callback",
	"auth-error",
	"auth-redirect",
]);
export default async function Page({
	params,
}: {
	params: Promise<{ authView: string }>;
}) {
	const { authView } = await params;
	if (!paths.has(authView)) notFound();
	return <AllAuthAuth path={authView} />;
}

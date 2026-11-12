import { HostedProjectAuthPage } from "@/components/hosted-project-auth-page";
import type { HostedProjectAuthPageProps } from "@/components/hosted-project-auth-page";

export default function Page(props: HostedProjectAuthPageProps) {
	return <HostedProjectAuthPage view="signUp" {...props} />;
}

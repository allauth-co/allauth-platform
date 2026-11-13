import { headers } from "next/headers";
import { notFound } from "next/navigation";
import { DeviceApproval } from "@/components/features/device";
import { HostedProjectUnavailable } from "@/components/hosted-project-unavailable";
import {
	devicePageCode,
	hostedDeviceProject,
	hostedDeviceReviewPath,
} from "@/lib/features/project-device-page";
import { isProjectWriterUnavailable } from "@/lib/projects/project-engine-unavailable";

export const metadata = { referrer: "no-referrer" } as const;

export default async function DevicePage({
	searchParams,
}: {
	searchParams: Promise<{
		project?: string | string[];
		user_code?: string | string[];
	}>;
}) {
	const params = await searchParams;
	if (params.project !== undefined) notFound();
	let project: string | undefined;
	try {
		project = await hostedDeviceProject(new Headers(await headers()));
	} catch (error) {
		if (isProjectWriterUnavailable(error)) return <HostedProjectUnavailable />;
		if (error instanceof Error && "statusCode" in error && error.statusCode === 403)
			notFound();
		throw error;
	}
	if (!project) notFound();
	return (
		<DeviceApproval
			key={project}
			project={project}
			initialCode={devicePageCode(params.user_code)}
			basePath="/api/auth"
			reauthentication={{
				signInURL: "/sign-in",
				returnPath: hostedDeviceReviewPath,
			}}
		/>
	);
}

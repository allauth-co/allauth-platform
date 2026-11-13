import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { DeviceApproval } from "@/components/features/device";
import { HostedProjectUnavailable } from "@/components/hosted-project-unavailable";
import { deviceProject } from "@/lib/features/device";
import { devicePageCode, projectDevicePage } from "@/lib/features/project-device-page";
import { isProjectWriterUnavailable } from "@/lib/projects/project-engine-unavailable";

export const metadata = { referrer: "no-referrer" } as const;

function InvalidDeviceProject() {
	return (
		<p role="alert" className="text-destructive">
			The device request contains an invalid project. Reopen the link from
			your device.
		</p>
	);
}

export default async function DevicePage({
	searchParams,
}: {
	searchParams: Promise<{
		project?: string | string[];
		user_code?: string | string[];
	}>;
}) {
	const params = await searchParams;
	let project: string | undefined;
	try {
		project = deviceProject(params.project);
	} catch {
		return <InvalidDeviceProject />;
	}
	const code = devicePageCode(params.user_code);
	if (!project) return <DeviceApproval initialCode={code} />;
	let target: Awaited<ReturnType<typeof projectDevicePage>>;
	try {
		target = await projectDevicePage(project, code, new Headers(await headers()));
	} catch (error) {
		if (isProjectWriterUnavailable(error)) return <HostedProjectUnavailable />;
		if (error instanceof Error && "statusCode" in error && error.statusCode === 404)
			return <InvalidDeviceProject />;
		throw error;
	}
	if (target.redirectTo) redirect(target.redirectTo);
	return (
		<DeviceApproval
			key={project}
			project={project}
			initialCode={code}
			basePath={target.basePath}
			reauthentication={target.reauthentication}
		/>
	);
}

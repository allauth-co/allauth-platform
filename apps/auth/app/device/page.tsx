import { DeviceApproval } from "@/components/features/device";
import { deviceProject } from "@/lib/features/device";

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
		return (
			<p role="alert" className="text-destructive">
				The device request contains an invalid project. Reopen the link from
				your device.
			</p>
		);
	}
	const code =
		typeof params.user_code === "string" && params.user_code.length <= 200
			? params.user_code
			: "";
	return (
		<DeviceApproval
			key={project ?? "__platform"}
			project={project}
			initialCode={code}
		/>
	);
}

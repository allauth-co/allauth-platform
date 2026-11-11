import Link from "next/link";
import { requireConsolePageScope } from "@/lib/console/page-scope";
import { featureInventory, featureStatusLabels } from "@/lib/features/status";

export const dynamic = "force-dynamic";

export default async function PluginsPage({
	searchParams,
}: {
	searchParams: Promise<{ project?: string | string[] }>;
}) {
	const { env, selected } = await requireConsolePageScope((await searchParams).project);
	const features = featureInventory(env, {
		project: Boolean(selected),
		projectSlug: selected?.slug,
		providerLibrariesInstalled: true,
	});
	return (
		<section className="space-y-5">
			<div>
				<h2 className="text-xl font-semibold">Authentication plugins</h2>
				<p className="text-sm text-muted-foreground mt-1">
					{selected ? selected.name : "AllAuth platform"} · Free plugin code is
					separate from hosting costs and external provider charges.
				</p>
			</div>
			<p className="text-sm text-muted-foreground">
				Installed libraries needing an account, credentials or an incompatible
				flow stay inactive. Test helpers never run in production. Enabled
				features retain the project's session and access boundaries.
			</p>
			<div className="border rounded-lg overflow-x-auto">
				<table className="w-full text-left text-sm">
					<thead className="bg-muted/50">
						<tr>
							<th className="p-4">Feature</th>
							<th className="p-4">Status</th>
							<th className="p-4 min-w-72">Availability</th>
						</tr>
					</thead>
					<tbody>
						{features.map((feature) => (
							<tr key={feature.id} className="border-t align-top">
								<td className="p-4">
									<Link
										href={feature.documentation}
										className="font-medium hover:underline"
										target="_blank"
										rel="noreferrer"
									>
										{feature.name}
									</Link>
									<p className="text-xs text-muted-foreground mt-1">
										{feature.installed
											? "Code installed"
											: "Installation pending"}
									</p>
								</td>
								<td className="p-4 whitespace-nowrap">
									{featureStatusLabels[feature.status]}
								</td>
								<td className="p-4 text-muted-foreground">{feature.detail}</td>
							</tr>
						))}
					</tbody>
				</table>
			</div>
		</section>
	);
}

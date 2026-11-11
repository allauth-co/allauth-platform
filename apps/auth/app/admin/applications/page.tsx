import { ApplicationsManagement } from "@/components/management/applications";
import { requireConsolePageScope } from "@/lib/console/page-scope";
import { authOrigin } from "@/lib/configuration";
import { publicProject } from "@/lib/projects/registry";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export default async function ApplicationsPage({ searchParams }: { searchParams: Promise<{ project?: string | string[] }> }) {
	const { env: environment, selected } = await requireConsolePageScope((await searchParams).project);
	if (selected) {
		const record = publicProject(selected);
		return <Card><CardHeader><CardTitle>Connect {record.name}</CardTitle><CardDescription>This integration uses this project's separate user store. Register one project for each app that needs independent users and organizations.</CardDescription></CardHeader><CardContent className="space-y-4 text-sm"><p>Primary app: <code className="break-all">{record.primaryOrigin}</code></p><p>Project auth API: <code className="break-all">{authOrigin(environment)}{record.authPath}</code></p><p>Use the AllAuth React components through your app's <code>/api/allauth</code> server route. Manage the server integration key in Projects.</p><p>Google sign-in uses the configured AllAuth identity connection and creates a separate account within this project.</p><p className="text-muted-foreground">The platform's Applications screen manages existing OAuth clients that share the platform identity store. Project integrations use the project-specific API above.</p></CardContent></Card>;
	}
	const issuer = authOrigin(environment);
	return <ApplicationsManagement issuer={issuer} />;
}

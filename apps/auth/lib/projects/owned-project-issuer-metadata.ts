import { allAuthIssuerMetadata } from "../issuer-metadata";
import { projectOrigin, projectSlug } from "./validation";

/** Discovery for a project issuer with an origin already selected by the ingress. */
export function ownedProjectIssuerMetadata(options: {
	origin: string;
	basePath: string;
	slug: string;
}) {
	const origin = projectOrigin.parse(options.origin);
	const slug = projectSlug.parse(options.slug);
	if (!["/api/auth", `/api/projects/${slug}/auth`].includes(options.basePath))
		throw new Error("Invalid project issuer path.");
	const issuer = origin + options.basePath;
	return allAuthIssuerMetadata({ origin, issuer, endpoints: issuer });
}

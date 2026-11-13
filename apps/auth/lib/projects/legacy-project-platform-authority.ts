import { dispatchPlatformAuth, withAuth, withAuthEngine } from "../auth";
import { projectBrokerTwoFactor } from "./broker-two-factor";
import type { ProjectPlatformAuthority } from "./owned-project-runtime-factory";

export const legacyProjectPlatformAuthority: ProjectPlatformAuthority = {
	readPrincipal(headers) {
		return withAuthEngine((root) => root.readPrincipal(headers));
	},
	verifyBrokerFactor(request, project, platformOrigin, factor) {
		return withAuth((root, env) =>
			projectBrokerTwoFactor(
				request,
				project,
				root,
				platformOrigin,
				factor,
				(input) => dispatchPlatformAuth(input, root, env),
				env,
			),
		);
	},
};

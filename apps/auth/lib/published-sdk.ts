import manifest from "./published-sdk.json";

const optional = new Set(
	Object.entries(manifest.peerDependenciesMeta)
		.filter(([, options]) => options.optional)
		.map(([name]) => name),
);

/** Installation guidance follows the served artifact while SDK source is in development. */
export const publishedSdkVersion = manifest.version;
export const publishedSdkPeers = Object.entries(manifest.peerDependencies)
	.filter(([name]) => !optional.has(name));
export const publishedSdkInstallPeers = publishedSdkPeers
	.filter(([name]) => name !== "react" && name !== "react-dom")
	.map(([name, range]) => `${name}@${range}`);

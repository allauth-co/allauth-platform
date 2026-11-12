import { existsSync } from "node:fs";
import { loadEnvFile } from "node:process";
import { Pool } from "pg";
import { setting } from "../../lib/configuration";
import { verifyProjectEncryptedSamlEvidence } from "../../lib/projects/owned-project-sso-saml-evidence";
import { getProject, projectRegistryPool } from "../../lib/projects/registry";

async function sampleFromStdin(): Promise<unknown> {
	if (process.stdin.isTTY) throw new Error();
	const decoder = new TextDecoder("utf-8", { fatal: true });
	let body = "";
	let bytes = 0;
	for await (const chunk of process.stdin as AsyncIterable<Uint8Array>) {
		bytes += chunk.byteLength;
		if (bytes > 270 * 1024) throw new Error();
		body += decoder.decode(chunk, { stream: true });
	}
	return JSON.parse(body + decoder.decode());
}

async function run() {
	const [slug, providerId, ...rest] = process.argv.slice(2);
	if (!slug || !providerId || rest.length) {
		process.stderr.write(
			"Pass a project slug and SAML provider ID, with the sample JSON on stdin.\n",
		);
		process.exitCode = 1;
		return;
	}
	if (existsSync(".env.local")) loadEnvFile(".env.local");
	const env = {};
	const connectionString = setting(env, "DATABASE_URL");
	if (!connectionString) throw new Error();
	const input = await sampleFromStdin();
	const database = new Pool({
		connectionString,
		max: 2,
		connectionTimeoutMillis: 5000,
		options: "-c statement_timeout=10000 -c lock_timeout=5000",
	});
	try {
		const project = await getProject(slug, env);
		const evidence = await verifyProjectEncryptedSamlEvidence({
			database,
			project,
			env,
			providerId,
			input,
		});
		process.stdout.write(`${JSON.stringify(evidence)}\n`);
	} finally {
		await Promise.all([database.end(), projectRegistryPool(env).end()]);
	}
}

// The XML library can write parser or crypto diagnostics. This operator process
// returns only the projected evidence or a fixed error message.
console.error = () => {};
console.warn = () => {};
try {
	await run();
} catch {
	process.stderr.write(
		"The encrypted SAML preflight sample could not be verified.\n",
	);
	process.exitCode = 1;
}

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readFile, stat } from "node:fs/promises";
import { dirname, join } from "node:path";
import { setTimeout } from "node:timers/promises";
import { promisify } from "node:util";

const execute = promisify(execFile);
const uuid = /^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/;
const syntheticDatabase = /^allauth_engine_rehearsal_[a-f0-9]{32}$/;
const deploying = new Set([
	"QUEUED",
	"WAITING",
	"INITIALIZING",
	"BUILDING",
	"DEPLOYING",
]);

interface Profile {
	project: string;
	environment: string;
	app: string;
	database: string;
	domain: string;
	baseRevision: string;
	source: string;
	restored: string;
	authSecret: string;
	edgeSecret: string;
	credentialSecret: string;
	databasePassword: string;
	databaseNonce: string;
}

interface Deployment {
	id: string;
	status: string;
	meta?: { cliMessage?: string };
}

interface EnvironmentStatus {
	id: string;
	name: string;
	serviceInstances: {
		edges: Array<{ node: { serviceId: string; serviceName: string } }>;
	};
}

interface ServiceInstance {
	serviceId: string;
	environmentId: string;
	numReplicas: number | null;
	overlapSeconds: number | null;
	activeDeployments: Array<Pick<Deployment, "id" | "status">>;
}

/** Connect the shared rehearsal to a separately provisioned, synthetic Railway project. */
export async function createRailwayProjectEngineTransport(profilePath: string) {
	assert.equal(
		(await stat(profilePath)).mode & 0o077,
		0,
		"Keep the fixture profile private.",
	);
	const profile = JSON.parse(await readFile(profilePath, "utf8")) as Profile;
	const { project, environment, app, database, domain, source, restored } =
		profile;
	assert.ok(
		[project, environment, app, database].every((value) => uuid.test(value)),
	);
	assert.ok([source, restored].every((value) => syntheticDatabase.test(value)));
	assert.notEqual(source, restored);
	assert.match(domain, /^[a-z0-9-]+\.up\.railway\.app$/);
	assert.match(profile.baseRevision, /^[a-f0-9]{7,40}$/);
	assert.ok(
		[
			profile.authSecret,
			profile.edgeSecret,
			profile.credentialSecret,
			profile.databasePassword,
			profile.databaseNonce,
		].every((value) => /^[a-f0-9]{64}$/.test(value)),
	);

	const scope = ["--project", project, "--environment", environment];
	const appScope = [...scope, "--service", app];
	const env = {
		...process.env,
		RAILWAY_CALLER: "skill:use-railway@1.7.0",
		RAILWAY_AGENT_SESSION:
			process.env.RAILWAY_AGENT_SESSION ??
			`allauth-compiled-rehearsal-${project}`,
	};
	async function railway(args: string[], action: string) {
		try {
			return (
				await execute("railway", args, { env, timeout: 30_000 })
			).stdout.trim();
		} catch {
			// Command arguments can contain synthetic fixture credentials.
			throw new Error(`Railway could not ${action}.`);
		}
	}

	const status = JSON.parse(
		await railway(
			["status", ...scope, "--json"],
			"verify the rehearsal project",
		),
	) as {
		id: string;
		name: string;
		environments: { edges: Array<{ node: EnvironmentStatus }> };
	};
	assert.equal(status.id, project);
	assert.match(status.name, /^allauth-rehearsal-[a-f0-9]{8}$/);
	assert.equal(status.environments.edges.length, 1);
	const staging = status.environments.edges[0]?.node;
	assert.ok(staging);
	assert.equal(staging.id, environment);
	assert.equal(staging.name, "staging");
	assert.deepEqual(
		new Map(
			staging.serviceInstances.edges.map(({ node }) => [
				node.serviceId,
				node.serviceName,
			]),
		),
		new Map([
			[app, "rehearsal-app"],
			[database, "rehearsal-db"],
		]),
	);
	const ingress = JSON.parse(
		await railway(
			["domain", "list", ...appScope, "--json"],
			"verify the rehearsal app hostname",
		),
	) as { domains: Array<{ domain: string; type: string; targetPort: number }> };
	assert.equal(ingress.domains.length, 1);
	assert.ok(
		ingress.domains.some(
			(entry) =>
				entry.domain === domain &&
				entry.type === "service" &&
				entry.targetPort === 3000,
		),
	);
	const databaseNetwork = JSON.parse(
		await railway(
			["tcp-proxy", "list", ...scope, "--service", database, "--json"],
			"verify private-only database access",
		),
	) as { proxies: unknown[] };
	assert.equal(databaseNetwork.proxies.length, 0);

	async function graphQL<T>(
		document: string,
		variables: Record<string, string>,
	) {
		const result = JSON.parse(
			await railway(
				[
					"api",
					document,
					"--variables",
					JSON.stringify(variables),
					"--compact",
				],
				"verify staging deployment authority",
			),
		) as { data?: T } & T;
		return result.data ?? result;
	}
	const instanceFields =
		"serviceId environmentId numReplicas overlapSeconds activeDeployments { id status }";
	const config = await graphQL<{
		environment: {
			id: string;
			projectId: string;
			config: {
				services: Record<
					string,
					{
						deploy: {
							overlapSeconds?: number;
							multiRegionConfig?: Record<string, { numReplicas: number }>;
						};
					}
				>;
			};
		};
		serviceInstance: ServiceInstance;
	}>(
		`query RehearsalConfiguration($project: String!, $environment: String!, $service: String!) {
			environment(id: $environment, projectId: $project) { id projectId config(decryptVariables: false) }
			serviceInstance(serviceId: $service, environmentId: $environment) { ${instanceFields} }
		}`,
		{ project, environment, service: app },
	);
	assert.equal(config.environment.id, environment);
	assert.equal(config.environment.projectId, project);
	assert.equal(config.serviceInstance.serviceId, app);
	assert.equal(config.serviceInstance.environmentId, environment);
	const deploy = config.environment.config.services[app]?.deploy;
	const replicas = deploy?.multiRegionConfig
		? Object.values(deploy.multiRegionConfig).reduce(
				(total, region) => total + region.numReplicas,
				0,
			)
		: config.serviceInstance.numReplicas;
	assert.equal(replicas, 1, "A staging rehearsal requires one app replica.");
	assert.equal(
		deploy?.overlapSeconds ?? config.serviceInstance.overlapSeconds,
		0,
		"A staging rehearsal requires zero deployment overlap.",
	);

	async function activeDeployments() {
		const { serviceInstance } = await graphQL<{
			serviceInstance: ServiceInstance;
		}>(
			`query RehearsalDeployments($environment: String!, $service: String!) {
				serviceInstance(serviceId: $service, environmentId: $environment) { ${instanceFields} }
			}`,
			{ environment, service: app },
		);
		assert.equal(serviceInstance.serviceId, app);
		assert.equal(serviceInstance.environmentId, environment);
		return serviceInstance.activeDeployments;
	}

	let active: Deployment | undefined;
	async function deployments() {
		return JSON.parse(
			await railway(
				["deployment", "list", ...appScope, "--limit", "12", "--json"],
				"read the rehearsal app deployments",
			),
		) as Deployment[];
	}

	async function waitForDeployment(message: string) {
		for (let attempt = 0; attempt < 150; attempt++) {
			const current = (await deployments()).find(
				(entry) => entry.meta?.cliMessage === message,
			);
			if (current) {
				assert.match(current.id, uuid);
				active = current;
				if (current.status === "SUCCESS") {
					const writers = await activeDeployments();
					if (writers.length) {
						assert.deepEqual(
							writers.map(({ id }) => id),
							[current.id],
							"The rehearsal phase must be the only active app deployment.",
						);
						console.log(`${message} succeeded (${current.id})`);
						return;
					}
				} else if (!deploying.has(current.status))
					throw new Error(
						`${message} ended with ${current.status} (${current.id}).`,
					);
			}
			await setTimeout(2000);
		}
		throw new Error(`${message} did not become ready.`);
	}

	return {
		profile,
		async query(db: string, sql: string) {
			assert.ok(db === "postgres" || db === source || db === restored);
			const escaped = sql.replaceAll("'", "'\\''");
			return railway(
				[
					"ssh",
					...scope,
					"--service",
					database,
					"--",
					`psql -X -U postgres -d ${db} -v ON_ERROR_STOP=1 -tAq -c '${escaped}'`,
				],
				"run a query inside the private synthetic database",
			);
		},
		async start(variant: string, db: string, values: Record<string, string>) {
			assert.equal(active, undefined);
			assert.ok(variant === "release" || variant === "candidate");
			assert.ok(db === source || db === restored);
			const prefix = `AllAuth rehearsal ${profile.baseRevision}`;
			if (db === source) {
				assert.equal(variant, "release");
				await waitForDeployment(`${prefix} legacy baseline`);
				return;
			}
			const message = `${prefix} ${variant === "candidate" ? "owned candidate" : "legacy rollback"}`;
			const current = await deployments();
			assert.deepEqual(await activeDeployments(), []);
			assert.ok(
				current.every(
					(entry) => entry.status !== "SUCCESS" && !deploying.has(entry.status),
				),
			);
			assert.ok(!current.some((entry) => entry.meta?.cliMessage === message));
			const settings = {
				DATABASE_URL: `postgresql://postgres:${profile.databasePassword}@rehearsal-db.railway.internal:5432/${db}`,
				...values,
			};
			await railway(
				[
					"variable",
					"set",
					...appScope,
					"--skip-deploys",
					...Object.entries(settings).map(([key, value]) => `${key}=${value}`),
				],
				"configure the restored synthetic rehearsal app",
			);
			await railway(
				[
					"up",
					join(dirname(profilePath), variant),
					"--path-as-root",
					...appScope,
					"--detach",
					"--message",
					message,
				],
				"upload the verified rehearsal source snapshot",
			);
			await waitForDeployment(message);
		},
		async stop() {
			if (!active) return;
			const deployment = active.id;
			const current = (await deployments()).find(
				(entry) => entry.id === deployment,
			);
			if (!current || current.status === "REMOVED") {
				active = undefined;
				return;
			}
			const result = JSON.parse(
				await railway(
					[
						"api",
						"mutation StopRehearsal($id: String!) { deploymentRemove(id: $id) }",
						"--variables",
						JSON.stringify({ id: deployment }),
						"--compact",
					],
					"stop the verified rehearsal app deployment",
				),
			) as { data?: { deploymentRemove: boolean }; deploymentRemove?: boolean };
			assert.equal(
				result.data?.deploymentRemove ?? result.deploymentRemove,
				true,
			);
			for (let attempt = 0; attempt < 45; attempt++) {
				const current = (await deployments()).find(
					(entry) => entry.id === deployment,
				);
				if (!current || current.status === "REMOVED") {
					active = undefined;
					console.log(`Stopped Railway deployment ${deployment}`);
					return;
				}
				await setTimeout(1000);
			}
			throw new Error(
				`Railway did not stop rehearsal deployment ${deployment}.`,
			);
		},
	};
}

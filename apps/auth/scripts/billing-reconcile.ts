import { existsSync } from "node:fs";
import { loadEnvFile } from "node:process";
import { processBillingJobs, reconcileWorkspaceBilling } from "../lib/billing/jobs";
import { billingConfiguration } from "../lib/billing/configuration";
import { projectRegistryPool } from "../lib/projects/registry";

if (existsSync(".env.local")) loadEnvFile(".env.local");
const env = process.env;
const configuration = billingConfiguration(env);
if (!configuration.configured) throw new Error("Configure the hosted Stripe account, mode, Price and restricted credentials before reconciliation.");
if (configuration.livemode && !process.argv.includes("--live")) throw new Error("Live billing reconciliation requires the explicit --live flag.");
const workspace = process.argv.find((value) => value.startsWith("--workspace="))?.slice("--workspace=".length);
try {
	if (workspace) console.info(JSON.stringify({ reconciled: await reconcileWorkspaceBilling(workspace, env) }));
	else console.info(JSON.stringify(await processBillingJobs(env, { maximum: 5, periodic: true })));
} finally { await projectRegistryPool(env).end(); }

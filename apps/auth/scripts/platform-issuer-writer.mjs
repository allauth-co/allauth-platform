import { existsSync } from "node:fs";
import { loadEnvFile } from "node:process";
import { Pool } from "pg";

const [operation, expected, revision, next, ...extra] = process.argv.slice(2);
const writers = new Set(["legacy", "allauth"]);
const reading = operation === "status" && expected === undefined;
if (
	!reading &&
	(operation !== "switch" ||
		extra.length ||
		!writers.has(expected) ||
		!writers.has(next) ||
		expected === next ||
		!/^(0|[1-9]\d{0,9})$/.test(revision ?? "") ||
		Number(revision) >= 2_147_483_647)
)
	throw new Error(
		"Usage: node scripts/platform-issuer-writer.mjs status | switch <expected-writer> <expected-revision> <next-writer>",
	);
if (existsSync(".env.local")) loadEnvFile(".env.local");
if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required.");

const database = new Pool({
	connectionString: process.env.DATABASE_URL,
	max: 1,
	connectionTimeoutMillis: 5000,
	statement_timeout: 20000,
	lock_timeout: 15000,
});
try {
	const {
		rows: [state],
	} = reading
		? await database.query(
				`SELECT writer,revision FROM public."allauthPlatformIssuerWriter" WHERE singleton`,
			)
		: await database.query(
				`SELECT writer,revision FROM public.allauth_switch_platform_issuer_writer($1,$2,$3)`,
				[expected, Number(revision), next],
			);
	if (!state) throw new Error("Missing shared issuer writer row.");
	console.log(JSON.stringify(state));
} catch (error) {
	if (error?.code === "AU002")
		throw new Error(
			"The shared issuer writer revision changed. Read status before retrying.",
		);
	throw new Error(
		"Could not complete the shared issuer writer operation. Read status before retrying.",
	);
} finally {
	await database.end();
}

#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createClient } from "./client.js";
import { login, logout } from "./login.js";
import { createServer, environmentFlag, VERSION } from "./server.js";
import { publicErrorMessage } from "./errors.js";
import { loginDevice } from "./device-login.js";
import { importClerkBatch, parseImportClerkArguments } from "./import-clerk.js";

const help = `AllAuth MCP ${VERSION}

Usage: allauth-mcp [start | login | logout | doctor | import-clerk] [--url https://allauth.co]

  start    Serve MCP on stdin/stdout (default). No browser or local HTTP listener.
  login    Show a one-time device approval link for Google or other AllAuth sign-in.
  logout   Remove the saved session for this origin from this computer.
  doctor   Check the current session against the workspace management API.
  import-clerk --project <exact-slug> --input <private-batch.json> --out <new-private-result.json> [--apply]
           Dry-run a private Clerk batch; only --apply enables import writes.

Login defaults to device approval. Use --method password for email/password and MFA;
that method accepts --email you@example.com. Passwords and MFA codes are never CLI arguments.
After device approval, AllAuth may also require TOTP or a recovery code in this terminal.
Environment: ALLAUTH_URL, ALLAUTH_COOKIE_FILE (or ALLAUTH_COOKIE),
             ALLAUTH_READ_ONLY=true, ALLAUTH_ALLOW_SENSITIVE=true.
See INSTALL.md for Codex, Claude Code, Claude Desktop and skill installation.
`;

async function main() {
	const args = process.argv.slice(2);
	if (args.includes("--help") || args.includes("-h")) { process.stdout.write(help); return; }
	if (args.length === 1 && args[0] === "--version") { process.stdout.write(`${VERSION}\n`); return; }
	let command = "start";
	if (args[0] && !args[0].startsWith("-")) command = args.shift()!;
	if (!["start", "login", "logout", "doctor", "import-clerk"].includes(command)) throw new Error("Unknown command. Use --help.");
	if (command === "import-clerk") { await importClerkBatch(parseImportClerkArguments(args)); return; }
	let baseURL: string | undefined;
	let email: string | undefined;
	let method = "device";
	while (args.length) {
		const flag = args.shift();
		const value = args.shift();
		if (!value || value.startsWith("--")) throw new Error("Each option needs a value. Use --help.");
		if (flag === "--url") baseURL = value;
		else if (flag === "--email" && command === "login") email = value;
		else if (flag === "--method" && command === "login") method = value;
		else throw new Error("Unknown option. Use --help.");
	}
	if (baseURL) process.env.ALLAUTH_URL = baseURL;
	if (command === "login") {
		if (method === "device" && !email) await loginDevice({ baseURL });
		else if (method === "password") await login({ baseURL, email });
		else throw new Error("Choose --method device, or --method password with an optional --email.");
		process.stderr.write("AllAuth login succeeded. The session is saved in your private credential store.\n");
		return;
	}
	if (command === "logout") { await logout({ baseURL }); process.stderr.write("The local AllAuth session was removed for this origin.\n"); return; }
	if (command === "doctor") {
		const client = await createClient({ baseURL });
		await client.request({ method: "GET", path: "/api/workspaces" });
		process.stdout.write(`${JSON.stringify({ authenticated: true, origin: client.baseURL, readOnly: environmentFlag("ALLAUTH_READ_ONLY"), allowSensitive: environmentFlag("ALLAUTH_ALLOW_SENSITIVE") }, null, 2)}\n`);
		return;
	}
	const server = createServer();
	const stop = async () => { await server.close(); process.exit(0); };
	process.once("SIGINT", () => { void stop(); });
	process.once("SIGTERM", () => { void stop(); });
	await server.connect(new StdioServerTransport());
}

main().catch((error: unknown) => {
	// Do not echo argument values, server errors or credential parser failures.
	process.stderr.write(`${publicErrorMessage(error) ?? "AllAuth MCP could not complete the command. Check --help, the configured origin and private credentials. For an expired session, run login again."}\n`);
	process.exitCode = 1;
});

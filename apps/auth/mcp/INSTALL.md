# Install AllAuth for agents

The AllAuth MCP server gives Codex, Claude Code, Claude Desktop, and other stdio MCP clients direct access to the hosted service's management APIs. The companion `allauth` skill teaches agents how to select an environment and carry out supported operations.

This is a local stdio server. `https://allauth.co` is the service origin, not a remote MCP endpoint. The package is distributed from this repository or a locally built archive; it is not published to a package registry.

## Build and sign in

Use Node.js 22.14 or newer and pnpm. From this repository:

```sh
pnpm --dir apps/auth/mcp install --frozen-lockfile
pnpm --dir apps/auth/mcp build
pnpm --dir apps/auth/mcp run login --url https://allauth.co
pnpm --dir apps/auth/mcp run doctor
```

By default, `login` uses device authorization. It prints an approval URL and a short user code in the terminal; it does not open the browser automatically. Open that URL yourself, sign in to AllAuth with Google, and approve the code for AllAuth MCP. Use the AllAuth account that owns or administers the target workspace. A Google account does not need an AllAuth password for this flow.

The CLI waits for that one browser approval. If AllAuth requires MFA, return to the terminal and complete its hidden TOTP or one-use recovery-code prompt; this can be required even if you completed MFA in the browser. Keep those codes in the local prompt. The CLI then verifies workspace access and saves the signed AllAuth session privately. Subsequent management calls run without the browser until the session expires. The approval request expires if it is not completed; a denial or authentication error stops the flow.

If the terminal MFA step fails or is cancelled, run `login` again and approve the new device code. The previous grant has already been consumed and cannot be polled again; its partial MFA challenge is not saved as a management session.

Device login requires the accompanying AllAuth server integration to be deployed. Source changes alone do not establish that a running service supports it. If the device exchange does not return the signed management session, the CLI saves nothing; deploy the matching server version and sign in again.

For an account with an AllAuth email/password credential, choose terminal-only login explicitly:

```sh
pnpm --dir apps/auth/mcp run login --method password --url https://allauth.co
```

Enter its email and password in the interactive terminal prompt, then complete TOTP or a one-use recovery code if requested. This method cannot sign in a Google-only account using its Google password. It does not add an AllAuth password to the account.

Use `pnpm run login` when running from the source package: `pnpm login` is pnpm's separate registry-login command. You can also run `node /absolute/path/AllAuth/apps/auth/mcp/dist/index.js login --url https://allauth.co` directly.

The MCP server uses cookie authentication after either login method. The device flow's access token is not sent as a management bearer token or used as a cookie. An application API key is not a substitute for a management session. Do not put a password, session cookie, user code, or recovery code in a repository or agent prompt.

## Distribute a local package

To produce an installable archive without publishing:

```sh
pnpm --dir apps/auth/mcp pack --pack-destination /absolute/path/package-output
```

In a separate tools project, install the returned archive and authenticate:

```sh
pnpm add /absolute/path/package-output/allauth-mcp-0.1.1.tgz
pnpm exec allauth-mcp login --url https://allauth.co
pnpm exec allauth-mcp doctor
```

Use the archive filename printed by `pack` if it differs. In the client examples below, replace the repository executable with `/absolute/path/tools-project/node_modules/@allauth/mcp/dist/index.js`, and copy the skill from that installed package's `skills/allauth/`. The archive includes built code and skills; the receiving machine still needs the package's runtime dependencies installed by pnpm.

## Codex

Register the built server using an absolute path:

```sh
codex mcp add allauth -- node /absolute/path/AllAuth/apps/auth/mcp/dist/index.js
```

Alternatively, merge this table into `~/.codex/config.toml` (or a trusted project's `.codex/config.toml`):

```toml
[mcp_servers.allauth]
command = "node"
args = ["/absolute/path/AllAuth/apps/auth/mcp/dist/index.js"]

[mcp_servers.allauth.env]
ALLAUTH_URL = "https://allauth.co"
```

For an inspection-only connection add `ALLAUTH_READ_ONLY = "true"` to the environment table. If Node is unavailable in the desktop app's PATH, replace `node` with its absolute executable path.

Install the skill by copying the entire directory, preserving `SKILL.md` and `agents/`:

```sh
mkdir -p "$HOME/.agents/skills"
cp -R /absolute/path/AllAuth/apps/auth/mcp/skills/allauth "$HOME/.agents/skills/"
```

If an `allauth` skill already exists, inspect it before replacing it. For a shared repository, put it in `.agents/skills/allauth/` instead. Open a new Codex chat after configuring the server, then use `$allauth` or ask to inspect your AllAuth workspaces. Check registration with `codex mcp list`; registration alone does not prove login or an operation succeeded.

## Claude Code

Register the same executable for your user:

```sh
claude mcp add --scope user --transport stdio allauth -- node /absolute/path/AllAuth/apps/auth/mcp/dist/index.js
```

Copy the skill to Claude Code's skill directory:

```sh
mkdir -p "$HOME/.claude/skills"
cp -R /absolute/path/AllAuth/apps/auth/mcp/skills/allauth "$HOME/.claude/skills/"
```

Use `.claude/skills/allauth/` for a project skill. Review an existing skill before replacing it. Start a fresh session, check `/mcp`, then invoke `/allauth` or describe the AllAuth task. `claude mcp get allauth` shows the server's configuration and connection status.

For a team configuration, use `--scope project`, which writes `.mcp.json`. Share only executable paths and nonsecret configuration; each person signs in locally. When using a nondefault AllAuth origin, pass `ALLAUTH_URL` to the server's environment as well as the login command.

## Claude Desktop

Open the local MCP configuration through Claude Desktop's Developer settings (or Local MCP servers under Extensions, depending on the installed layout). Merge this entry into the existing `mcpServers` object:

```json
{
  "mcpServers": {
    "allauth": {
      "command": "node",
      "args": ["/absolute/path/AllAuth/apps/auth/mcp/dist/index.js"],
      "env": {
        "ALLAUTH_URL": "https://allauth.co"
      }
    }
  }
}
```

On macOS the configuration is `~/Library/Application Support/Claude/claude_desktop_config.json`; on Windows it is `%APPDATA%\Claude\claude_desktop_config.json`. Use an absolute Node executable path if needed. Fully quit and reopen Claude Desktop, then inspect the local server's connection and tools.

This local configuration does not create a remote connector for claude.ai or Cowork. Those clients need a publicly reachable remote MCP service. The supplied skill can be used where that client supports custom skills, but it still requires access to the MCP tools.

## Other MCP clients

Choose the stdio transport, command `node`, and argument `/absolute/path/AllAuth/apps/auth/mcp/dist/index.js`. Set `ALLAUTH_URL` for a custom service origin. Start the process as the same operating-system user who completed login, or explicitly configure its credential source. Clients that support Agent Skills can install `skills/allauth/` in their own documented skill location.

## Credential sources and controls

Either login method saves sessions keyed by exact service origin in `$XDG_CONFIG_HOME/allauth/credentials.json`, falling back to `~/.config/allauth/credentials.json`. The store uses file mode `600` and directory mode `700` on POSIX. Set `ALLAUTH_CREDENTIALS_FILE` to choose another private store location.

For an existing authorized session, `ALLAUTH_COOKIE` supplies a raw Cookie header. `ALLAUTH_COOKIE_FILE` selects an absolute path to a UTF-8 file containing that raw header, with mode `600` on POSIX and no symlink. These are alternatives to the login store. Do not commit a credential file or put the cookie in shared agent configuration.

`ALLAUTH_READ_ONLY=true` hides and blocks write tools locally. `ALLAUTH_ALLOW_SENSITIVE=true` enables tools that can return secrets, including integration credentials. Enable those only for the required task. Service authorization remains authoritative for all tools. Default tool availability does not expand the user's account permissions.

`logout` removes the matching session from the local login store; it does not revoke the remote session. Separately unset or remove `ALLAUTH_COOKIE` and `ALLAUTH_COOKIE_FILE` overrides when those supply the connection.

## Verify and troubleshoot

Run `doctor` in a terminal to inspect connectivity, then ask the agent to list accessible workspaces and projects. The server exposes `allauth://capabilities`, `allauth://guide`, and the `allauth_setup` and `allauth_investigate_user` prompts.

- A `401` generally means the session is absent or expired. Run interactive login again, then reconnect the MCP client.
- A device login that completes approval but cannot obtain a management session requires the matching server integration. The CLI does not store the device access token as a substitute credential.
- A `403` means the account lacks the required service permission or verification. Signing in does not grant new roles.
- A `404` can indicate a management capability is unavailable on that deployment. Report it rather than switching environments.
- Keep the selected workspace and exact project slug visible. Development and Production have independent account data and settings.
- The built executable writes MCP protocol messages to stdout. Run login separately in a terminal; a startup wrapper must not print a login banner or other text to stdout.

## Client documentation

Configuration details were checked against the official [Codex MCP documentation](https://learn.chatgpt.com/docs/extend/mcp), [Codex skills documentation](https://learn.chatgpt.com/docs/build-skills), [Claude Code MCP documentation](https://code.claude.com/docs/en/mcp), [Claude Code skills documentation](https://code.claude.com/docs/en/skills), and [MCP local-server guide for Claude Desktop](https://modelcontextprotocol.io/docs/develop/connect-local-servers). Desktop menu names and organization policy can vary by installed client.

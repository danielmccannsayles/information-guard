> [!CAUTION]
> Not extensively reviewed or tested. The sandbox uses macOS `sandbox-exec` with `(allow default)` (fail-open). It restricts file reads, and can be configured to prevent writes, but doesn't touch network, process execution, or other operations.

> [!NOTE]
> **Update (Aug 11): Claude's sandboxing approach has changed.** Claude now uses its own built-in sandbox (enabled via `sandbox.enabled` in `~/.claude/settings.json`) plus permission deny rules — not the `information-guard-sandbox` process wrapper. The deny rules are generated from `sandbox.json` via `information-guard-sandbox --print-claude-config`. See [`docs/claude-native-sandbox.md`](docs/claude-native-sandbox.md) for details.

# information-guard

Protects your system from AI agents, with two layers:

1. **Git guard** — prevents agents from committing/pushing to protected repos. Uses an env var (`AGENT_FLAG`) set by the agent's extension, checked by global git hooks.

2. **File sandbox** — a whole-process macOS Seatbelt sandbox. A sandbox can restrict three things: **reads**, **writes**, and **network**. This one does the first two:
   - **Reads** — protected paths are unreadable at the kernel level (EPERM on `open()`). The core feature: your private data stays private.
   - **Writes** (on by default) — denied outside the workspace, temp dirs, and tool state dirs. Catastrophic-mistake protection: `rm -rf ~` dies on the first visible file.
   - **Network** — untouched, deliberately. This is the trade you make vs other sandboxes; see [the comparison](#compared-to-other-sandboxes) below.

## How it works

### Git guard

Agents (pi, Claude Code, etc.) set an `AGENT_FLAG` env var on every bash command they run. The git hooks check for this env var and block commit/push in repos listed in `~/.config/information-guard/repos.txt`.

- **pi**: `git-guard.ts` extension prepends `export AGENT_FLAG=pi;` to every bash command
- **Claude Code**: `SessionStart` hook writes `export AGENT_FLAG=claude` to `$CLAUDE_ENV_FILE`
- **Git hooks**: `~/.config/git/hooks/pre-commit` and `pre-push` (identical scripts, symlinked from `git-guard/hook.sh`)

To add a new agent: set `AGENT_FLAG=<name>` in the agent's environment before it runs bash commands.

### File sandbox

The sandbox wrapper (`sandbox/sandbox.mjs`) generates a Seatbelt profile that denies reads/writes to protected paths, then runs the command via `sandbox-exec -p`:

```
information-guard-sandbox claude
└─ sandbox-exec -p '(allow default) + write containment + protected-path denies'
   └─ claude
      ├─ Bash tool  → sandboxed (EPERM on protected paths)
      ├─ Read tool  → sandboxed (EPERM on protected paths)
      ├─ Edit tool  → sandboxed (EPERM on protected paths)
      └─ MCP servers → sandboxed
```

Network, keychain, TTY, and mach IPC are all untouched. The profile is `(allow default)` with deny rules for each protected path, plus the write containment below.

### Write containment

On by default (`writeContainment.enabled` in the config), the profile denies all writes except:

- the **workspace** — the directory the agent was launched from (note: launch from `~` and your whole home directory is the workspace)
- temp dirs (`$TMPDIR` and its per-user parent, `/private/tmp`) and `/dev`
- **home-root dotfiles** (`~/.claude`, `~/.codex`, `~/.npm`, ...) — the heuristic that avoids per-agent allowlists: hidden files at the root of home are tool state, visible files are your data. Any agent's state keeps working with zero configuration; `rm -rf ~` dies on the first visible file. Symlinked dotfiles are resolved at launch (Seatbelt matches resolved paths), so `~/.claude → ~/agents/claude` works.
- your configured `allowWrite` paths (escape hatch, usually empty)

Minus a deny list of sensitive dotfiles that wins over the dotfile allow: shell startup files (`~/.zshrc`, `~/.bashrc`, `~/.profile`, ...), credentials (`~/.ssh`, `~/.aws`, `~/.netrc`, `~/.gnupg`, `~/.docker`, `~/.config/gh`, `~/.tinfoil`), git integrity (`~/.gitconfig`, `~/.config/git`), the guard's own config (`~/.config/information-guard`), and PATH executables (`~/.local/bin`, `~/.cargo/bin`, `~/.nvm`, `~/.pyenv`, ...). These are write-denied only — agents can still read/exec them (e.g. run `node` from `~/.nvm`), just not modify them. For read-protection, add paths to `protectedPaths` in the config instead. Sensitive dotfiles are stable across agents and years; agent state dirs churn — hence deny-list the former, heuristic-allow the latter.

Protected-path denies are emitted last, so a protected dir inside an allowed root stays blocked (SBPL: later rules win). This gives you Codex-style "read the computer, only mutate the project" semantics while leaving network and everything else untouched.

Debug with `information-guard-sandbox --print-profile`, and run the test matrix with `sandbox/test-containment.sh` (from a normal terminal — Seatbelt doesn't nest, so it refuses to run inside a wrapped session).

## Install

_Requires macOS (uses `sandbox-exec` / Seatbelt)._

```bash
./install.sh
```

Copies `sandbox.mjs` and `hook.sh` into `~/.config/information-guard/` and `~/.config/git/hooks/` (both write-denied by the sandbox), then symlinks `~/.local/bin/information-guard-sandbox` to the copied `sandbox.mjs`. The repo source stays a dev copy — edits are inert until you re-run `install.sh` from a human terminal. Re-run it after updating the repo.

```bash
# ~/.zshrc
alias pi='information-guard-sandbox pi'
```

Claude uses its built-in sandbox instead (see [Claude Code's built-in sandbox](#claude-codes-built-in-sandbox)) — no wrapper alias. Enable it via `sandbox.enabled` in `~/.claude/settings.json`, generated by `information-guard-sandbox --print-claude-config`.

The wrapped command's basename selects a profile from the config (`profiles.pi` for the second alias), so per-agent behavior needs nothing in the alias — see Config.

## Config

Set protected repos (no git push & commit) and paths (no read/write)

### `~/.config/information-guard/repos.txt`

```
~/agents
~/projects/some-protected-repo
```

### `~/.config/information-guard/sandbox.json`

```json
{
  "protectedPaths": ["~/secrets", "~/agent-config/memory"],
  "writeContainment": {
    "enabled": true,
    "allowWrite": []
  },
  "profiles": {
    "pi": { "protectedPaths": [] }
  }
}
```

Omit `writeContainment` (or set `enabled: false`) for protected-paths-only behavior. `allowWrite` is an escape hatch for tools whose state lives outside home-root dotfiles.

**Profiles**: the top-level config is the default; `profiles.<name>` applies to commands whose basename matches `<name>`. A key present in the profile replaces the top-level value; a key absent is inherited. The example above gives pi full read access while keeping write containment — a trusted agent still gets catastrophe protection. (`$INFORMATION_GUARD_CONFIG` overrides the config file location entirely, mostly for testing.)

## Compared to other sandboxes

On the reads / writes / network axes:

|                                 | reads                         | writes                          | network               |
| ------------------------------- | ----------------------------- | ------------------------------- | --------------------- |
| **information-guard**           | deny protected paths          | workspace-contained             | untouched             |
| **Claude Code native sandbox**  | deny paths (Bash + Read tool) | workspace-contained (Bash only) | untouched             |
| `@anthropic-ai/sandbox-runtime` | deny paths                    | workspace-contained             | mandatory allowlist   |
| Codex (workspace-write)         | deny paths                    | workspace-contained             | off, or allowlist/`*` |

### Claude Code's built-in sandbox

**Use it** — for Claude specifically, the built-in sandbox is the recommended path (same as Codex below). Claude's sandbox only wraps the **Bash tool**, so the main process (auth, keychain, Read/Edit/Write tools) runs unsandboxed. This matters: wrapping the whole process with `information-guard-sandbox` blocks keychain writes (so OAuth token refresh can't persist) and setuid exec (`/bin/ps` can't run).

`information-guard-sandbox --print-claude-config` emits the deny rules + sandbox config from your `sandbox.json`, so the same config covers both approaches. See [`docs/claude-native-sandbox.md`](docs/claude-native-sandbox.md) for setup and the full tradeoff.

The tradeoff: the built-in sandbox gates Read/Edit/Write at the permission layer, not the kernel. An MCP server reading files directly bypasses both. If you need kernel-level Read protection on the Read tool, wrap with `information-guard-sandbox` instead — but you'll lose keychain and setuid support.

### Why not sandbox-runtime?

`npx @anthropic-ai/sandbox-runtime claude` wraps the whole process like information-guard does, and adds network control — but the network config is a mandatory allowlist that rejects `*` as "overly broad". There is no way to say "leave the network alone"; you must enumerate every domain the agent may touch, and unlisted domains are blocked silently. If that ceremony is worth it to you, use it. Switching from sandbox-runtime to information-guard, the only thing you lose is network restriction — reads and writes are covered comparably.

### What about permissions.deny?

Claude Code's `permissions.deny` (e.g. `Read(**/secrets/**)`) is pattern matching on tool invocations. On its own it can be bypassed via the Bash tool (`python3 -c "open('secret').read()"`) or an MCP server reading files directly. But with the native sandbox enabled, Claude **merges `Read(...)` deny rules into the Bash sandbox profile** — so the Bash bypass is closed at the kernel level. The MCP bypass remains: an MCP server reading files directly isn't gated by either the deny rules or the sandbox. For MCP-resistance, wrap with `information-guard-sandbox` (kernel-level on the whole process) instead.

### Codex / other sandboxed tools

Apple sandboxes do not nest. If you're using e.g. Codex, which has its own apple sandbox, add your configuration directly to Codex's sandbox instead of wrapping it. To keep `sandbox.json` the single source of truth, generate the Codex profile from it:

```bash
information-guard-sandbox --print-codex-config
```

```toml
# Generated by information-guard from ~/.config/information-guard/sandbox.json
# Paste into ~/.codex/config.toml. Re-run after changing protectedPaths.

default_permissions = "information-guard"

[permissions.information-guard]
description = "Workspace-write with deny-read on information-guard protected paths."
extends = ":workspace"

[permissions.information-guard.filesystem]
"~/agents/pi/agent/memory" = "deny"
"~/agents/fragments/encrypted" = "deny"
"~/agents/pi/agent/extensions" = "deny"
"~/agents/pi/agent/sessions" = "deny"
"~/agents/remember" = "deny"
```

Only the read-denies need syncing — Codex's `:workspace` base already contains writes to the workspace (and disables network for sandboxed commands; add `[permissions.information-guard.network]` with `enabled = true` and `domains = { "*" = "allow" }` if you want Codex to match information-guard's open-network posture).

## License

MIT

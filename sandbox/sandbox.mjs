#!/usr/bin/env node
// information-guard sandbox — wraps a command in a macOS Seatbelt sandbox.
//
// Two layers:
//   1. Protected paths — reads/writes to protected paths are denied at the
//      kernel level (EPERM on open()). Always on.
//   2. Write containment (optional) — writes are denied everywhere except:
//        - the workspace (the directory the agent was launched from)
//        - temp dirs and /dev
//        - home-root dotfiles (~/.claude, ~/.codex, ~/.npm, ...) — agent and
//          tool state, agent-agnostic, no per-agent allowlist to maintain —
//          minus a deny list of sensitive dotfiles (credentials, shell
//          startup, PATH executables, the guard's own config)
//        - configured allowWrite paths (escape hatch for weird tools)
//      Mirrors codex's workspace-write sandbox: the agent can read the
//      computer but only mutate the project it was launched in.
//
// Everything else is allowed: network, keychain, TTY, mach IPC, sysctls.
// Uses a raw SBPL profile built on (allow default). Later rules take
// precedence over earlier ones, so the order is: allow default → containment
// deny + allows → sensitive-dotfile denies → protected-path denies (later
// denies win over the allows, e.g. a protected dir inside an allowed
// workspace stays blocked).
//
// Usage: information-guard-sandbox <command> [args...]
//        information-guard-sandbox --print-profile [name]      (show the generated SBPL and exit)
//        information-guard-sandbox --print-codex-config [name]  (emit a codex permissions profile
//                                                                 from the same config, to paste into
//                                                                 ~/.codex/config.toml — codex has its
//                                                                 own Seatbelt sandbox; don't wrap it)
//        information-guard-sandbox --print-claude-config [name] (emit a claude-code settings block
//                                                                 from the same config, to paste into
//                                                                 ~/.claude/settings.json — claude has
//                                                                 its own sandbox; don't wrap it)
//
// The wrapped command's basename selects a profile from `profiles` in the
// config (if one matches), so per-agent behavior needs nothing in the alias:
// `information-guard-sandbox pi` uses profiles.pi.
// Config: ~/.config/information-guard/sandbox.json (override with $INFORMATION_GUARD_CONFIG)
//   {
//     "protectedPaths": ["~/path/..."],
//     "writeContainment": { "enabled": true, "allowWrite": [] }
//   }
//
// install.sh copies this source to ~/.config/information-guard/sandbox.mjs
// (write-denied) and symlinks ~/.local/bin/information-guard-sandbox to it.
// The repo source is editable but inert — edits only take effect after
// re-running install.sh from a human terminal. ~/.local/bin is also
// write-denied (in WRITE_PROTECTED_DOTFILES), so the symlink itself can't be
// repointed by a sandboxed agent.

import {
  existsSync,
  readFileSync,
  readdirSync,
  realpathSync,
  statSync,
} from "node:fs";
import { homedir } from "node:os";
import { spawn } from "node:child_process";
import { join, dirname, basename } from "node:path";

const CONFIG_PATH =
  process.env.INFORMATION_GUARD_CONFIG ||
  join(homedir(), ".config", "information-guard", "sandbox.json");

// Dotfiles agents may never write, even though dotfiles are writable in
// general (the dotfile allow-regex covers tool state like ~/.npm, ~/.claude).
// These win over the allow because they're persistence vectors (shell startup,
// PATH executables that run as you) or credentials/tamper targets. Stable
// across agents and years, unlike per-agent state-dir allowlists.
// Write-deny only (file-write*); reads are unaffected — agents can still
// exec tools in ~/.local/bin or read ~/.aws/credentials. For read-protection
// on credentials in the Claude native config, see READ_PROTECTED_CREDENTIALS
// below (the wrapper keeps reads open so subprocess tools like gh/aws work).
// For read-protection in the wrapper itself, add paths to protectedPaths.
// Credentials and secrets — read+write protected in the Claude native
// config (--print-claude-config emits Read+Edit deny), but write-protected
// only in the wrapper (so subprocess tools like gh/aws can still read their
// own credentials to function).
const READ_PROTECTED_CREDENTIALS = [
  "~/.ssh",
  "~/.aws",
  "~/.netrc",
  "~/.gnupg",
  "~/.docker",
  "~/.config/gh", // gh auth tokens (hosts.yml)
  "~/.tinfoil",
];

// Other sensitive dotfiles — write-protected only (reads allowed) in both
// the wrapper and the Claude native config. These are persistence vectors
// (shell startup, PATH executables that run as you) or tamper targets
// (git integrity, the guard's own config). Agents can still read/exec them
// (e.g. run node from ~/.nvm, read ~/.gitconfig) but not modify them.
const WRITE_PROTECTED_DOTFILES = [
  // Shell startup (persistence via sourced rc files)
  "~/.zshrc",
  "~/.zshrc.backup",
  "~/.zprofile",
  "~/.zshenv",
  "~/.zlogin",
  "~/.bashrc",
  "~/.bash_profile",
  "~/.profile",
  // Git integrity (hooks, identity)
  "~/.gitconfig", // core.hooksPath — git-guard integrity
  "~/.config/git", // the git-guard hooks themselves
  // The guard itself (config + copied source after install)
  "~/.config/information-guard",
  // PATH executables (run-as-you, unsandboxed — prevents command shadowing)
  "~/.local/bin",
  "~/.bun/bin",
  "~/.cargo/bin",
  "~/.foundry/bin",
  "~/.nebius/bin",
  "~/.nvm", // node version manager (write-deny; running node still works)
  "~/.pyenv", // python version manager (same)
];

// Expand ~ in paths
function expandPath(p) {
  if (p.startsWith("~/")) return join(homedir(), p.slice(2));
  if (p === "~") return homedir();
  return p;
}

// Contract an absolute path back to ~/ form (for emitting portable config)
function tildePath(p) {
  const home = homedir();
  if (p === home) return "~";
  if (p.startsWith(home + "/")) return "~" + p.slice(home.length);
  return p;
}

// Seatbelt matches on resolved paths (e.g. /tmp → /private/tmp), so resolve
// symlinks where possible. Nonexistent paths are kept as-is.
function realPath(p) {
  try {
    return realpathSync(p);
  } catch {
    return p;
  }
}

// For a path, return the glob pattern(s) for Claude Code deny rules.
// Existing dir → ["~/path/**"]. Existing file → ["~/path"]. Non-existent →
// both (covers either case when the path is created later; re-run
// --print-claude-config after creating new sensitive paths).
function claudeDenyGlobs(path) {
  const tilded = tildePath(path);
  try {
    if (statSync(path).isDirectory()) return [`${tilded}/**`];
    return [tilded];
  } catch {
    return [tilded, `${tilded}/**`];
  }
}

// Resolved targets of symlinked home-root dotfiles. Seatbelt matches resolved
// paths, so the dotfile regex alone misses state dirs that are symlinks
// (~/.claude → ~/agents/claude). Enumerate them at launch and allow the
// targets explicitly.
function dotfileSymlinkTargets() {
  const home = homedir();
  const targets = [];
  let entries = [];
  try {
    entries = readdirSync(home);
  } catch {
    return targets;
  }
  for (const name of entries) {
    if (!name.startsWith(".")) continue;
    const p = join(home, name);
    const real = realPath(p);
    if (real !== p) targets.push(real);
  }
  return targets;
}

// Load config from ~/.config/information-guard/sandbox.json.
//
// Profiles: the top-level config is the default. `profiles.<name>` overrides
// it for commands whose basename matches <name> — a key present in the
// profile replaces the top-level value, a key absent is inherited. So
// `"profiles": { "pi": { "protectedPaths": [] } }` gives pi the same write
// containment but no read-denies.
function loadConfig(profileName) {
  if (!existsSync(CONFIG_PATH)) {
    console.error(`information-guard: No config found at ${CONFIG_PATH}`);
    console.error("  Run the install script or create it with:");
    console.error(`    mkdir -p ~/.config/information-guard`);
    console.error(
      `    echo '{"protectedPaths":["~/secrets"]}' > ${CONFIG_PATH}`,
    );
    process.exit(1);
  }

  const raw = JSON.parse(readFileSync(CONFIG_PATH, "utf8"));
  let cfg = raw;
  const profile = profileName ? raw.profiles?.[profileName] : undefined;
  if (profile) {
    cfg = {
      protectedPaths:
        "protectedPaths" in profile
          ? profile.protectedPaths
          : raw.protectedPaths,
      writeContainment:
        "writeContainment" in profile
          ? profile.writeContainment
          : raw.writeContainment,
    };
  }

  const protectedPaths = (cfg.protectedPaths || []).map(expandPath);
  const containment = {
    enabled: cfg.writeContainment?.enabled === true,
    allowWrite: (cfg.writeContainment?.allowWrite || []).map(expandPath),
  };

  if (protectedPaths.length === 0 && !containment.enabled) {
    console.error(
      "information-guard: No protectedPaths and no writeContainment in config. Nothing to sandbox.",
    );
    process.exit(1);
  }

  return { protectedPaths, containment };
}

// Build the SBPL profile. (allow default) permits everything; containment
// (if enabled) denies writes and re-allows specific roots; sensitive-dotfile
// and protected-path denies come last so they take precedence over the
// containment allows.
function buildProfile(protectedPaths, containment) {
  const lines = ["(version 1)", "(allow default)"];

  if (containment.enabled) {
    lines.push(`(deny file-write* (subpath "/"))`);

    // Workspace, temp, /dev, symlinked-dotfile targets, config extras
    const subpathAllows = new Set([
      realPath(process.cwd()),
      "/private/tmp",
      "/dev",
    ]);
    if (process.env.TMPDIR) {
      // $TMPDIR plus its parent (the per-user /private/var/folders dir,
      // which also holds the C/ cache sibling)
      const tmp = realPath(process.env.TMPDIR);
      subpathAllows.add(tmp);
      subpathAllows.add(dirname(tmp));
    }
    for (const t of dotfileSymlinkTargets()) subpathAllows.add(t);
    for (const p of containment.allowWrite) subpathAllows.add(realPath(p));
    for (const p of subpathAllows) {
      lines.push(`(allow file-write* (subpath "${p}"))`);
    }

    // Home-root dotfiles: tool and agent state (~/.claude, ~/.codex, ~/.npm,
    // ~/.local, ...). Visible files in home stay write-denied — that's the
    // data containment protects.
    lines.push(`(allow file-write* (regex #"^${homedir()}/\\.[^/]*(/|$)"))`);

    // Sensitive dotfiles and credentials win over the regex allow
    for (const s of [
      ...READ_PROTECTED_CREDENTIALS,
      ...WRITE_PROTECTED_DOTFILES,
    ]) {
      lines.push(`(deny file-write* (subpath "${realPath(expandPath(s))}"))`);
    }
  }

  // Deny file-read-data (content + directory listing) but allow file-read-metadata
  // (stat, lstat). This lets git status stat files without reading their contents.
  // git may warn about directories it can't list, but exit code and output are correct.
  // file-write* is fully denied (no writes to protected paths).
  for (const p of protectedPaths) {
    lines.push(
      `(deny file-read-data (subpath "${p}"))`,
      `(deny file-write* (subpath "${p}"))`,
    );
  }

  return lines.join("\n");
}

function main() {
  const command = process.argv.slice(2);
  if (command.length === 0) {
    console.error("Usage: information-guard-sandbox <command> [args...]");
    process.exit(1);
  }

  // Profile selection: the wrapped command's basename (information-guard-sandbox
  // pi → profile "pi"). For the --print-* flags, an optional trailing arg names
  // the profile (--print-profile pi).
  const isPrintFlag = command[0].startsWith("--print-");
  const profileName = isPrintFlag ? command[1] : basename(command[0]);
  const { protectedPaths, containment } = loadConfig(profileName);
  const profile = buildProfile(protectedPaths, containment);

  if (command[0] === "--print-profile") {
    console.log(profile);
    process.exit(0);
  }

  // Codex has its own Seatbelt sandbox (Apple sandboxes don't nest), so
  // instead of wrapping it, emit an equivalent permissions profile from the
  // same config. ":workspace" already contains writes and disables network;
  // only the protected-path read-denies need syncing.
  if (command[0] === "--print-codex-config") {
    console.log(
      [
        `# Generated by information-guard from ${CONFIG_PATH}`,
        `# Paste into ~/.codex/config.toml. Re-run after changing protectedPaths.`,
        ``,
        `default_permissions = "information-guard"`,
        ``,
        `[permissions.information-guard]`,
        `description = "Workspace-write with deny-read on information-guard protected paths."`,
        `extends = ":workspace"`,
        ``,
        `[permissions.information-guard.filesystem]`,
        ...protectedPaths.map((p) => `"${tildePath(p)}" = "deny"`),
      ].join("\n"),
    );
    process.exit(0);
  }

  // Claude Code has a built-in sandbox (sandbox-exec wrapping the Bash tool)
  // and permission deny rules. Unlike the process wrapper, the main process
  // (auth, keychain, Read/Edit/Write tools) stays unsandboxed — so keychain
  // writes work and setuid binaries like /bin/ps can run. See
  // docs/claude-native-sandbox.md for the full rationale.
  //
  // Emit protectedPaths + WRITE_PROTECTED_DOTFILES as Claude deny rules, and
  // writeContainment as the sandbox config. Read(...) deny rules also gate
  // the Bash tool (Claude merges them into the sandbox), so a protectedPath
  // is blocked at both the Read tool and Bash level. sandbox.json stays the
  // single source of truth — re-run after changing it.
  if (command[0] === "--print-claude-config") {
    const deny = [];
    for (const p of protectedPaths) {
      for (const g of claudeDenyGlobs(p)) {
        deny.push(`Read(${g})`);
        deny.push(`Edit(${g})`);
      }
    }
    // Credentials: read+write protected (the LLM should never read raw creds)
    for (const s of READ_PROTECTED_CREDENTIALS) {
      for (const g of claudeDenyGlobs(expandPath(s))) {
        deny.push(`Read(${g})`);
        deny.push(`Edit(${g})`);
      }
    }
    // Other sensitive dotfiles: write-protected only (reads allowed so
    // subprocess tools like gh/aws keep working when run via Bash)
    for (const s of WRITE_PROTECTED_DOTFILES) {
      for (const g of claudeDenyGlobs(expandPath(s))) {
        deny.push(`Edit(${g})`);
      }
    }

    const config = { permissions: { deny } };
    if (containment.enabled) {
      config.sandbox = {
        enabled: true,
        filesystem: {
          allowWrite: containment.allowWrite.map((p) => tildePath(p)),
        },
      };
    }

    console.log(
      [
        `// Generated by information-guard from ${CONFIG_PATH}`,
        `// Paste into ~/.claude/settings.json (merge into permissions.deny + sandbox).`,
        `// Re-run after changing protectedPaths or writeContainment.`,
        `//`,
        `// protectedPaths → Read+Edit deny (read+write protected)`,
        `// READ_PROTECTED_CREDENTIALS → Read+Edit deny (read+write protected — the LLM`,
        `//   should never read raw credentials; subprocess tools like gh/aws are also`,
        `//   blocked from reading them via the Bash sandbox)`,
        `// WRITE_PROTECTED_DOTFILES → Edit deny only (write-protected, reads allowed —`,
        `//   agents can still exec tools in ~/.local/bin, read ~/.gitconfig)`,
        JSON.stringify(config, null, 2),
      ].join("\n"),
    );
    process.exit(0);
  }

  // sandbox-exec -p '<profile>' -- <command>
  // The profile is passed as a single argument. sandbox-exec runs the command
  // inside the sandbox. stdio is inherited so TUI apps work normally.
  const child = spawn("/usr/bin/sandbox-exec", ["-p", profile, ...command], {
    stdio: "inherit",
  });

  child.on("exit", (code, signal) => {
    if (signal) {
      if (signal === "SIGINT" || signal === "SIGTERM") process.exit(0);
      console.error(`information-guard: process killed by signal: ${signal}`);
      process.exit(1);
    }
    process.exit(code ?? 0);
  });

  child.on("error", (err) => {
    console.error(`information-guard: ${err.message}`);
    process.exit(1);
  });
}

main();

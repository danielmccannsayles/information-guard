#!/bin/bash
# test-print-config.sh — validates the --print-claude-config and --print-codex-config
# generators. Fast (no claude binary needed). Uses a temp sandbox.json via
# $INFORMATION_GUARD_CONFIG so your real config is untouched.
#
# Run from anywhere: bash test-print-config.sh

set -u
SANDBOX="$(cd "$(dirname "$0")" && pwd)/sandbox.mjs"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/ig-print-test-XXXXXX")
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

export INFORMATION_GUARD_CONFIG="$WORK/config.json"

# A protected dir that exists (→ emits /**) and one that doesn't (→ emits both)
mkdir -p "$WORK/protected-dir"
PROTECTED_EXISTS="$WORK/protected-dir"
PROTECTED_MISSING="$WORK/protected-missing-dir"

cat > "$INFORMATION_GUARD_CONFIG" <<EOF
{
  "protectedPaths": ["$PROTECTED_EXISTS", "$PROTECTED_MISSING"],
  "writeContainment": { "enabled": true, "allowWrite": ["$WORK/allowed"] },
  "profiles": { "pi": { "protectedPaths": [] } }
}
EOF

pass=0
fail=0
ok()   { echo "  ok:  $1"; pass=$((pass + 1)); }
bad()  { echo "FAIL: $1"; fail=$((fail + 1)); }

# Extract the JSON payload from a --print-* output (strip // comment lines)
claude_json() { node "$SANDBOX" --print-claude-config 2>&1 | grep -v '^//'; }
codex_output() { node "$SANDBOX" --print-codex-config 2>&1; }

echo "=== --print-claude-config ==="

OUT=$(node "$SANDBOX" --print-claude-config 2>&1)
JSON=$(echo "$OUT" | grep -v '^//')

# Valid JSON?
echo "$JSON" | python3 -c "import json,sys; json.load(sys.stdin)" 2>/dev/null \
  && ok "emits valid JSON" || bad "emits invalid JSON"

# Helper: does the deny list contain a rule? (fixed-string match — rules
# contain regex metacharacters like ** and parens)
has_rule() { echo "$OUT" | grep -Fq "\"$1\"" && echo yes || echo no; }

# protectedPaths → Read + Edit (existing dir → /**)
[ "$(has_rule "Read($PROTECTED_EXISTS/**)")" = yes ] && ok "protectedPath (existing dir) → Read deny" || bad "protectedPath (existing dir) missing Read deny"
[ "$(has_rule "Edit($PROTECTED_EXISTS/**)")" = yes ] && ok "protectedPath (existing dir) → Edit deny" || bad "protectedPath (existing dir) missing Edit deny"

# protectedPaths → Read + Edit (non-existent → bare + /** both)
[ "$(has_rule "Read($PROTECTED_MISSING)")" = yes ] && ok "protectedPath (missing) → Read deny (bare)" || bad "protectedPath (missing) missing Read deny (bare)"
[ "$(has_rule "Read($PROTECTED_MISSING/**)")" = yes ] && ok "protectedPath (missing) → Read deny (/**)" || bad "protectedPath (missing) missing Read deny (/**)"

# READ_PROTECTED_CREDENTIALS → Read + Edit
[ "$(has_rule 'Read(~/.ssh/**)')" = yes ] && ok "credential (~/.ssh) → Read deny" || bad "credential (~/.ssh) missing Read deny"
[ "$(has_rule 'Edit(~/.ssh/**)')" = yes ] && ok "credential (~/.ssh) → Edit deny" || bad "credential (~/.ssh) missing Edit deny"
[ "$(has_rule 'Read(~/.aws/**)')" = yes ] && ok "credential (~/.aws) → Read deny" || bad "credential (~/.aws) missing Read deny"
[ "$(has_rule 'Read(~/.tinfoil/**)')" = yes ] && ok "credential (~/.tinfoil) → Read deny" || bad "credential (~/.tinfoil) missing Read deny"

# WRITE_PROTECTED_DOTFILES → Edit only (no Read)
[ "$(has_rule 'Edit(~/.zshrc)')" = yes ] && ok "dotfile (~/.zshrc) → Edit deny" || bad "dotfile (~/.zshrc) missing Edit deny"
[ "$(has_rule 'Read(~/.zshrc)')" = no ] && ok "dotfile (~/.zshrc) → no Read deny (reads allowed)" || bad "dotfile (~/.zshrc) has unexpected Read deny"
[ "$(has_rule 'Edit(~/.local/bin/**)')" = yes ] && ok "dotfile (~/.local/bin) → Edit deny" || bad "dotfile (~/.local/bin) missing Edit deny"
[ "$(has_rule 'Read(~/.local/bin/**)')" = no ] && ok "dotfile (~/.local/bin) → no Read deny" || bad "dotfile (~/.local/bin) has unexpected Read deny"

# sandbox block
echo "$JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); assert d['sandbox']['enabled'] is True" 2>/dev/null \
  && ok "sandbox.enabled = true" || bad "sandbox.enabled missing/wrong"
echo "$JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); assert '\"$WORK/allowed\"' in d['sandbox']['filesystem']['allowWrite'] or any('allowed' in p for p in d['sandbox']['filesystem']['allowWrite'])" 2>/dev/null \
  && ok "sandbox.filesystem.allowWrite from config" || bad "sandbox.filesystem.allowWrite missing"

echo
echo "=== --print-claude-config (containment off) ==="
cat > "$INFORMATION_GUARD_CONFIG" <<EOF
{ "protectedPaths": ["$PROTECTED_EXISTS"], "writeContainment": { "enabled": false } }
EOF
OUT=$(node "$SANDBOX" --print-claude-config 2>&1)
JSON=$(echo "$OUT" | grep -v '^//')
echo "$JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); assert 'sandbox' not in d" 2>/dev/null \
  && ok "no sandbox block when containment off" || bad "sandbox block present when containment off"

echo
echo "=== --print-claude-config (profile: pi drops protectedPaths) ==="
cat > "$INFORMATION_GUARD_CONFIG" <<EOF
{
  "protectedPaths": ["$PROTECTED_EXISTS"],
  "writeContainment": { "enabled": true, "allowWrite": [] },
  "profiles": { "pi": { "protectedPaths": [] } }
}
EOF
OUT=$(node "$SANDBOX" --print-claude-config pi 2>&1)
echo "$OUT" | grep -q "Read($PROTECTED_EXISTS" \
  && bad "pi profile should drop protectedPaths (still emitted)" || ok "pi profile drops protectedPaths"

echo
echo "=== --print-codex-config ==="
cat > "$INFORMATION_GUARD_CONFIG" <<EOF
{
  "protectedPaths": ["$PROTECTED_EXISTS"],
  "writeContainment": { "enabled": true, "allowWrite": [] }
}
EOF
CODEX=$(codex_output)
echo "$CODEX" | grep -q 'default_permissions = "information-guard"' && ok "codex: default_permissions set" || bad "codex: default_permissions missing"
echo "$CODEX" | grep -q "\"$PROTECTED_EXISTS\" = \"deny\"" && ok "codex: protectedPath as deny" || bad "codex: protectedPath missing"
echo "$CODEX" | grep -q 'extends = ":workspace"' && ok "codex: extends :workspace" || bad "codex: extends :workspace missing"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]

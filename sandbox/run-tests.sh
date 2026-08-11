#!/bin/bash
# run-tests.sh — run the information-guard test suite.
#
# Usage:
#   bash run-tests.sh              # run all suites (fast + slow)
#   bash run-tests.sh --skip-slow  # skip suites that need claude / a human terminal
#
# Suites:
#   test-print-config.sh    — generator output (fast, no claude, runs anywhere)
#   test-containment.sh     — wrapper sandbox (fast, no claude, human terminal)
#   test-claude-native.sh   — claude native sandbox + deny rules (slow, needs claude, human terminal)
#
# test-containment and test-claude-native refuse to run inside an
# information-guard-sandbox session (Seatbelt doesn't nest). Run from a
# normal terminal.

set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
SKIP_SLOW=0
for arg in "$@"; do
  case "$arg" in
    --skip-slow) SKIP_SLOW=1 ;;
    *) echo "unknown flag: $arg"; exit 2 ;;
  esac
done

suites=()
suites+=("test-print-config.sh")
[ "$SKIP_SLOW" -eq 0 ] && suites+=("test-containment.sh")
[ "$SKIP_SLOW" -eq 0 ] && suites+=("test-claude-native.sh")

total_pass=0
total_fail=0
for s in "${suites[@]}"; do
  echo
  echo "############################################"
  echo "# $s"
  echo "############################################"
  if bash "$DIR/$s"; then
    :
  else
    echo "(suite $s exited non-zero)"
  fi
done

echo
echo "All suites complete."

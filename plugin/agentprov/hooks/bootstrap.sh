#!/bin/sh
# Ensure the agentprov binary the hooks call is present and executable. The
# binary is committed at bin/agentprov (per-platform). If it's missing — e.g. a
# clone on a different OS/arch — try to build it from a sibling source checkout,
# else warn once and let the SessionEnd hook skip gracefully (fail-open).
BIN="${CLAUDE_PLUGIN_ROOT}/bin/agentprov"
[ -x "$BIN" ] && exit 0

# Try to build from a Go source dir if one is reachable (dev machine).
for SRC in "${CLAUDE_PLUGIN_ROOT}/../.." "$HOME/github/agentprov"; do
  if [ -f "$SRC/main.go" ] && command -v go >/dev/null 2>&1; then
    mkdir -p "${CLAUDE_PLUGIN_ROOT}/bin"
    ( cd "$SRC" && go build -o "$BIN" . ) >/dev/null 2>&1 && exit 0
  fi
done

printf '\033[33magentprov: recorder binary not found at %s — provenance recording is OFF for this session.\n  build it: cd <agentprov repo> && go build -o plugin/agentprov/bin/agentprov .\033[0m\n' "$BIN" 1>&2
exit 0

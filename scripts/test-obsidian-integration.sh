#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
PLUGIN_DIR="$REPO_ROOT/plugins/obsidian"
FIXTURE_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/disk-obsidian-it.XXXXXX")
LOG_FILE="$FIXTURE_ROOT/daemon.log"
DAEMON_PID=""

cleanup() {
    if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        kill -INT "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    rm -rf -- "$FIXTURE_ROOT"
}
trap cleanup EXIT INT TERM

if curl --silent --show-error --max-time 1 http://127.0.0.1:9444/status >/dev/null 2>&1; then
    echo "ERROR: port 9444 is already serving; refusing to run against a possibly live daemon" >&2
    exit 1
fi

echo "Building plugin_test_daemon fixture..."
cargo build -p disk-client --example plugin_test_daemon --quiet

cargo run -p disk-client --example plugin_test_daemon --quiet -- "$FIXTURE_ROOT" >"$LOG_FILE" 2>&1 &
DAEMON_PID=$!

ready=0
for _ in $(seq 1 300); do
    if curl --silent --fail --max-time 1 http://127.0.0.1:9444/status >/dev/null 2>&1; then
        ready=1
        break
    fi
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        sed -n '1,160p' "$LOG_FILE" >&2
        exit 1
    fi
    sleep 0.1
done
if [ "$ready" -ne 1 ]; then
    sed -n '1,160p' "$LOG_FILE" >&2
    echo "ERROR: daemon did not become ready on 127.0.0.1:9444" >&2
    exit 1
fi

(cd "$PLUGIN_DIR" && npm ci --silent)
(cd "$PLUGIN_DIR" && npm run test:integration)

test "$(cat "$FIXTURE_ROOT/docs/notes/todo.md")" = "remote version"
test "$(cat "$FIXTURE_ROOT/wiki/notes/todo.md")" = "wiki untouched"

kill -INT "$DAEMON_PID"
wait "$DAEMON_PID"
DAEMON_PID=""

# Reopen the production SQLite file and prove resolution persisted.
python3 - "$FIXTURE_ROOT/state/meta.db" <<'PY'
import sqlite3
import sys

with sqlite3.connect(sys.argv[1]) as db:
    row = db.execute(
        "SELECT vault_id, resolved, resolution FROM conflicts WHERE path = ?",
        ("notes/todo.md",),
    ).fetchone()
assert row == ("docs", 1, "keep-remote"), row
PY

echo "Obsidian integration PASS: real daemon :9444 + production SQLite/filesystem"

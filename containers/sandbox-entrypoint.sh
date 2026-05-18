#!/bin/bash
# Make /workspace world-accessible so the host user can read findings,
# reports, and engagement files without sudo.
# Security boundary is the container itself, not file permissions.
chmod -R 777 /workspace 2>/dev/null || true
# Ensure all NEW files are also world-readable/writable
umask 0000

# Optional HTTP daemon mode. When SANDBOX_DAEMON=1 the container drops
# its tail-forever keep-alive and runs the FastAPI sandbox server
# instead. Used by Cloud Run multi-container deploys where the agent
# can't `docker exec` into a sibling container and instead talks to
# this one over HTTP on localhost.
#
# Existing dev / local-docker / GCE Spot users don't set the env and
# get the unchanged behaviour (`exec "$@"` falls through to the
# Dockerfile CMD = tail -f /dev/null).
if [ "${SANDBOX_DAEMON:-0}" = "1" ]; then
    exec python3 -m decepticon.sandbox_server
fi

exec "$@"

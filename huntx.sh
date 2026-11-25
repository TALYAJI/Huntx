#!/usr/bin/env bash
# Create a virtualenv on first use, install HUNTX into it, then run it.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if [ ! -x .venv/bin/huntx ]; then
    python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))' || { echo "HUNTX needs Python 3.10+" >&2; exit 1; }
    python3 -m venv .venv
    .venv/bin/pip install --quiet -e .
fi
exec .venv/bin/huntx "$@"

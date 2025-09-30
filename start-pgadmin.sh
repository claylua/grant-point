#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PGADMIN_WEB_DIR="/Applications/pgAdmin 4.app/Contents/Resources/web"
PYTHONPATH="${SCRIPT_DIR}/pgadmin-config:${PGADMIN_WEB_DIR}" \
PGADMIN_SERVER_MODE=ON \
"/Applications/pgAdmin 4.app/Contents/Frameworks/Python.framework/Versions/3.9/bin/python3" \
"${PGADMIN_WEB_DIR}/pgAdmin4.py"

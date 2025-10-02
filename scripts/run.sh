#!/usr/bin/env bash
set -euo pipefail
if [ $# -lt 1 ]; then echo "usage: $0 <issuer-or-app-url>"; exit 1; fi
oidc-lint "$1" --json-out report.json
cat report.json | jq .

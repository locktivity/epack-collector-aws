#!/usr/bin/env bash
#
# Fails the build if the collector source references AWS APIs that read secret
# values. These APIs are forbidden because the collector emits posture metadata
# only; secret material must never enter the artifact.
#
# Forbidden APIs:
#   - secretsmanager:GetSecretValue   (Secrets Manager secret values)
#   - ssm:GetParameter / GetParameters with SecureString type   (SSM SecureString values)
#
# Escape hatch: prefix the call site with `// LINT-ALLOW: <reason>` if a future
# change has a legitimate reason to mention the symbol (e.g., a test asserting it
# was never invoked).

set -euo pipefail

cd "$(dirname "$0")/.."

violations=$(
  grep -rn -E 'GetSecretValue|GetParameter\(|GetParameters\(|GetParametersByPath\(' \
    internal/ \
    --include='*.go' \
    | grep -v '_test.go' \
    | grep -v '// LINT-ALLOW:' \
    || true
)

if [ -n "$violations" ]; then
  echo "FORBIDDEN AWS API CALLS DETECTED"
  echo "These APIs return secret material and must never appear in collector source:"
  echo "$violations"
  exit 1
fi

echo "forbidden-API check: OK"

#!/usr/bin/env bash
# Build the placeholder bootstrap.zip for first-time CFN stack deploy
# (ADR 001 §3, Implementation step 7).
#
# CloudFormation cannot create a Lambda function with an empty Code property,
# and `Code.ZipFile:` only supports managed runtimes (Node, Python) — not
# `provided.al2023`. So we ship a tiny custom-runtime placeholder that
# returns 502 stack_bootstrap_only on every invocation, until the first
# `lepre-api` CI run replaces it via `aws lambda update-function-code`.
#
# Usage:
#   bash scripts/build-placeholder.sh [out-dir]
#   aws s3 cp <out-dir>/bootstrap.zip s3://francescobarbera-releases/lepre/bootstrap.zip
set -euo pipefail

OUT_DIR="${1:-target/placeholder}"
mkdir -p "$OUT_DIR"

# Custom-runtime entrypoint: a POSIX shell loop against the Lambda runtime API.
# See https://docs.aws.amazon.com/lambda/latest/dg/runtimes-walkthrough.html
cat > "$OUT_DIR/bootstrap" <<'EOF'
#!/bin/sh
set -eu
while true; do
    HEADERS=$(mktemp)
    curl -sS -LD "$HEADERS" \
        "http://${AWS_LAMBDA_RUNTIME_API}/2018-06-01/runtime/invocation/next" \
        > /dev/null
    REQUEST_ID=$(grep -i '^Lambda-Runtime-Aws-Request-Id:' "$HEADERS" \
        | head -n1 | tr -d '\r' | awk '{print $2}')
    rm -f "$HEADERS"
    curl -sS -X POST \
        "http://${AWS_LAMBDA_RUNTIME_API}/2018-06-01/runtime/invocation/${REQUEST_ID}/response" \
        -d '{"statusCode":502,"headers":{"content-type":"application/json"},"body":"{\"error\":\"stack_bootstrap_only\",\"code\":502}"}' \
        > /dev/null
done
EOF
chmod +x "$OUT_DIR/bootstrap"

(cd "$OUT_DIR" && zip -q bootstrap.zip bootstrap)

echo "Placeholder ready: $OUT_DIR/bootstrap.zip"
echo "Upload with:"
echo "  aws s3 cp $OUT_DIR/bootstrap.zip s3://francescobarbera-releases/lepre/bootstrap.zip"

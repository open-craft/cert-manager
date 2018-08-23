#!/bin/sh

# This script is meant to be used as a deploy hook for certbot,

set -euo pipefail

first() {
    # Helper function to return first argument.
    echo "$1";
}

consul_prefix="${1:-ocim}"
consul_key="$consul_prefix/certs/$(first $RENEWED_DOMAINS).pem"

cd "$RENEWED_LINEAGE"

cat fullchain.pem privkey.pem |
    consul kv put "$consul_key" @/dev/stdin

#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$repo_dir/dist"
mojo build --emit shared-lib --target-features=+aes "$repo_dir/src/crypto.mojo" -o "$repo_dir/dist/libmojo-pycryptodome.so"

#!/usr/bin/env bash
# LCOV for local tools + same percentage table as plain `cargo llvm-cov` (CI only writes lcov).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
cargo llvm-cov --all-features --lcov --output-path lcov.info
exec cargo llvm-cov report

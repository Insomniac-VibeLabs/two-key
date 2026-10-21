#!/bin/sh
# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
# Writes each hashed CI requirements file (NAME.txt) from NAME.in. Run it with the uv in uv.in after changing a
# .in file: sh .github/requirements/compile.sh
# The resolution is universal (every OS, Python 3.10 and up) and wheels only, as CI installs them.
set -eu
cd "$(dirname "$0")"
for src in *.in; do
  out="${src%.in}.txt"
  {
    sed -n '1,3p' "$src"
    echo "# Generated from $src by compile.sh, with hashes; do not edit by hand."
    uv pip compile --quiet --universal --python-version 3.10 --generate-hashes --only-binary :all: \
      --no-header --no-annotate "$src"
  } > "$out.tmp"
  mv "$out.tmp" "$out"
done

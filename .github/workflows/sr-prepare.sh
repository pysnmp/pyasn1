#!/usr/bin/env bash

set -eE
set -v
# shellcheck disable=SC1091,SC2086
# Only build if dist directory is empty or doesn't exist
if [ ! -d "dist" ] || [ -z "$(ls -A dist)" ]; then
  echo "Building package with poetry"
  poetry build
else
  echo "Using existing build artifacts from dist directory"
fi

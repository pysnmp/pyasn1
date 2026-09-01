#!/usr/bin/env bash

set -eE
set -v
# shellcheck disable=SC1091,SC2086
# Create distributions but don't publish - publishing is done by the publish-to-pypi workflow
echo "Preparing release: Building distributions for version ${1:-unknown}"

rm -rf dist

uv build

echo "Distribution files prepared for publishing:"
ls -la dist/

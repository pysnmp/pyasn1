#!/usr/bin/env bash

set -eE
set -v
# shellcheck disable=SC1091,SC2086
# Create distributions but don't publish - publishing is done by the publish-to-pypi workflow
echo "Preparing release: Building distributions for version ${1:-unknown}"

rm -rf dist

# semantic-release has just rewritten the version in pyproject.toml, so uv.lock
# still records the previous one. CI installs with `uv sync --locked`, which
# fails on that skew, so refresh the lockfile before building.
uv lock

uv build

echo "Distribution files prepared for publishing:"
ls -la dist/

#!/usr/bin/env bash

set -eE
set -v
# shellcheck disable=SC1091,SC2086
# Create distributions but don't publish - publishing will be done by tox in the publish-to-pypi workflow
echo "Preparing release: Building distributions for version ${1:-unknown}"

# Clean existing dist directory to avoid mixing versions
if [ -d "dist" ]; then
  rm -rf dist
fi

# Create distribution using both poetry (for wheels) and build (for sdist)
python -m pip install --upgrade pip
python -m pip install build poetry
python -m build
echo "Distribution files prepared for publishing:"
ls -la dist/

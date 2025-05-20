#!/usr/bin/env bash

set -eE
set -v
# This script is no longer used by semantic-release, but kept as a reference
# or for manual publishing if needed.
# Publishing is now handled by the publish-to-pypi.yml workflow using tox.

echo "WARNING: This script is no longer used by the automated workflow."
echo "The publish-to-pypi.yml workflow will automatically handle publishing via tox."

# Only build if manually invoked
if [ "${MANUAL_PUBLISH:-0}" = "1" ]; then
  echo "Manual publishing requested"

  if [ -z "${PYPI_TOKEN}" ]; then
    echo "Error: PYPI_TOKEN environment variable not set"
    exit 1
  fi

  echo "Building package"
  python -m build

  echo "Publishing to PyPI"
  poetry config pypi-token.pypi ${PYPI_TOKEN}
  poetry publish -n
else
  echo "Skipping publish - use the GitHub Actions workflow instead"
  echo "For manual publishing, run with: MANUAL_PUBLISH=1 PYPI_TOKEN=your_token ./.github/workflows/sr-release.sh"
fi

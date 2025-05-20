#!/usr/bin/env bash

set -eE
set -v
# In the new workflow, we only want the sr-release.sh script to prepare the release
# but not actually publish to PyPI. The publishing will be done by the publish-to-pypi.yml workflow
# which is triggered when the tag is pushed

echo "Preparing release artifacts"
if [ ! -d "dist" ] || [ -z "$(ls -A dist)" ]; then
  echo "Building package with poetry"
  poetry build
else
  echo "Using existing build artifacts from dist directory"
fi

# No publishing here - publishing happens in the publish-to-pypi.yml workflow
echo "Package built successfully. Publishing will be handled by the publish-to-pypi.yml workflow."

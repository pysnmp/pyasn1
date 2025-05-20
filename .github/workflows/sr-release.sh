#!/usr/bin/env bash

set -eE
set -v
echo "Publishing to PyPI as user: ${PYPI_USERNAME}"
# Use poetry's modern auth approach with token
poetry config pypi-token.pypi ${PYPI_TOKEN}
# Use the dist directory that was downloaded from artifacts
if [ -d "dist" ] && [ "$(ls -A dist)" ]; then
  echo "Found build artifacts in dist directory"
  poetry publish -n
else
  echo "No build artifacts found in dist directory, building and publishing"
  poetry publish --build -n
fi

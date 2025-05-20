#!/usr/bin/env bash

set -eE
set -v
echo "Publishing to PyPI as user: ${PYPI_USERNAME}"
# Use poetry's modern auth approach with token
poetry config pypi-token.pypi ${PYPI_TOKEN}
poetry publish -n

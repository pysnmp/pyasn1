# Semantic Release Configuration

This project uses semantic-release for automating version management and package publishing.

## License

Copyright 2021 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## Configuration

The semantic-release configuration is stored in `.releaserc.json` and uses the following plugins:

- `@semantic-release/commit-analyzer` - Analyzes commit messages to determine the semantic version bump
- `@google/semantic-release-replace-plugin` - Updates version strings in Python files and pyproject.toml
- `@semantic-release/release-notes-generator` - Generates release notes
- `@semantic-release/exec` - Executes the prepare and publish scripts
- `@semantic-release/git` - Commits the updated files to git
- `@semantic-release/github` - Creates GitHub releases and adds assets

## Branches

Releases are handled on the following branches:
- `main` - Production releases
- `develop` - Beta releases (with the beta tag)

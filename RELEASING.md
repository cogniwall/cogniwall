# Releasing

1. Bump `version` in `pyproject.toml`
2. Commit and merge to `main`
3. Create a [GitHub Release](https://github.com/cogniwall/cogniwall/releases/new) with a tag matching the version (e.g. `v0.2.0`)
4. CI runs tests across Python 3.11–3.14, then publishes to PyPI automatically

> **Note:** PyPI uses the version from `pyproject.toml`, not the git tag. Make sure they match.

## First-time setup

Before the first release, complete these one-time steps:

1. **PyPI:** Go to [pypi.org](https://pypi.org) → your project → Settings → Publishing → add a new GitHub trusted publisher:
   - Owner: `cogniwall`, Repository: `cogniwall`, Workflow: `ci.yml`, Environment: `pypi`
2. **GitHub:** Go to repo Settings → Environments → create environment named `pypi`

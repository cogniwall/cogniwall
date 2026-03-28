# Contributing to CogniWall

Thanks for your interest in contributing! This guide will help you get started.

## Development Setup

1. **Clone the repo:**

   ```bash
   git clone https://github.com/cogniwall/cogniwall.git
   cd cogniwall
   ```

2. **Install in dev mode** (creates a `.venv` automatically):

   ```bash
   pip install -e ".[dev]"
   ```

3. **Run the tests:**

   ```bash
   .venv/bin/pytest -v
   ```

## Running Tests

```bash
# All tests (excludes live LLM tests by default)
.venv/bin/pytest -v

# A single test file
.venv/bin/pytest tests/test_rules/test_pii.py -v

# A single test
.venv/bin/pytest tests/test_rules/test_pii.py::TestPiiDetectionRule::test_blocks_ssn -v

# Robustness / adversarial tests
.venv/bin/pytest tests/test_robustness/ tests/test_adversarial_r4.py -v
```

## Adding a New Rule

1. Create `cogniwall/rules/<name>.py` with a class that extends `Rule` from `rules/base.py`.
2. Implement `tier`, `rule_name`, `async evaluate(payload) -> Verdict`, and `@classmethod from_config(config) -> Rule`.
3. Register it in `_RULE_REGISTRY` inside `cogniwall/config.py`.
4. Add validation in `_validate_rule_config` (same file).
5. Export from `cogniwall/rules/__init__.py` and `cogniwall/__init__.py`.
6. Add tests in `tests/test_rules/`.

## Pull Request Guidelines

- **One concern per PR.** Keep changes focused.
- **Add tests** for new rules or bug fixes.
- **Run the full test suite** before submitting.
- **Follow existing code style.** The codebase uses standard Python conventions — match what you see.
- **Write a clear PR description** explaining *what* changed and *why*.

## Reporting Bugs & Requesting Features

Use the [issue templates](https://github.com/cogniwall/cogniwall/issues/new/choose) on GitHub.

## Security Vulnerabilities

Please **do not** open a public issue for security vulnerabilities. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

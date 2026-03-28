# Changelog

All notable changes to CogniWall will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-03-25

### Added
- Core evaluation engine with tiered pipeline (classical rules first, LLM rules second)
- PII detection rule with custom term support and text normalization
- Financial limit rule with configurable field and threshold
- Prompt injection detection rule (Anthropic and OpenAI providers)
- Tone and sentiment analysis rule (Anthropic and OpenAI providers)
- Rate limiting rule with configurable window and key field
- YAML configuration support with duplicate key detection
- Async pipeline with parallel rule execution per tier
- `extract_strings` utility for deep payload traversal
- Text normalization pipeline (invisible char stripping, NFKD, leet, homoglyph, base64)
- `_safe_copy` for payload isolation without `deepcopy` RCE risk
- Audit client with async fire-and-forget event reporting
- Self-hosted Next.js audit dashboard with event log, drill-down, and analytics
- CI/CD with GitHub Actions (Python 3.11-3.14 test matrix, PyPI auto-publish)

[0.1.0]: https://github.com/cogniwall/cogniwall/releases/tag/v0.1.0

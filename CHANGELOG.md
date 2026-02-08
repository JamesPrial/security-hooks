# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.0] - 2026-02-08

### Added
- CI workflow: multi-OS (Ubuntu, macOS, Windows) and multi-Go-version (1.22, 1.23) test matrix
- Release workflow: cross-compiles binaries for 5 platforms (darwin/amd64, darwin/arm64, linux/amd64, linux/arm64, windows/amd64)
- Platform-detection wrapper script for automatic OS/architecture dispatch
- Orphan `releases` branch with pre-built binaries for marketplace distribution
- GitHub Releases with SHA256 checksums
- `make cover` target for coverage summary

### Changed
- Binary output moved from `scripts/check-secrets` to `bin/check-secrets`
- Makefile now uses `-trimpath -ldflags="-s -w"` for smaller, reproducible binaries
- Marketplace installs no longer require manual `make build`

## [1.0.1] - 2026-01-16

### Fixed
- Removed duplicate hooks field from plugin manifest

## [1.0.0] - 2025-12-28

### Added
- PreToolUse hook that scans staged files before git commits
- 24 pre-compiled regex patterns for secret detection:
  - AWS Access Key ID and Secret Access Key
  - API keys (OpenAI, Google, Anthropic, Hugging Face)
  - VCS tokens (GitHub PAT, OAuth, User, Server, Refresh)
  - Communication services (Slack, Discord, Twilio, SendGrid, Mailgun)
  - Payment services (Stripe secret and restricted keys)
  - Database connection strings (PostgreSQL, MySQL, MongoDB)
  - Private keys (RSA, DSA, EC, OpenSSH)
  - Bearer tokens and generic secret patterns
- .env file parsing with hardcoded value detection
- Binary file detection (30+ extensions skipped)
- 70+ unit tests across 12 test classes

### Security
- TOCTOU-safe implementation: reads from git staging area via `git show :filepath`
- Fail-closed design: exit code 2 blocks commits on errors
- Word boundary matching to prevent false positives on git commit detection

### Fixed
- Discord token pattern now correctly matches token format
- `is_git_commit_command` no longer triggers on unrelated commands containing "git" and "commit"

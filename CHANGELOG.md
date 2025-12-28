# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

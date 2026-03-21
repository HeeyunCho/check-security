# IMPLEMENTATION: Check Security

## Overview
A security-focused MCP server that performs static analysis on files and directories to detect known secret patterns and validate git configurations.

## Tools (Methods)

### 1. `scan_for_secrets`
**Description**: Recursively scans a path for regex patterns matching API keys, tokens, and private keys.
- **Parameters**:
  - `path` (string): Absolute path to scan.
- **Returns**: A list of findings or a success message.
- **Patterns**: Detects Generic API Keys, Slack Tokens, AWS Keys, GitHub PATs, Google Client IDs, and Private Keys.

### 2. `check_gitignore`
**Description**: Validates `.gitignore` content against a list of common sensitive file patterns.
- **Parameters**:
  - `path` (string): Path to `.gitignore` or the project root.
- **Returns**: A warning if critical patterns (like `.env`, `credentials.json`) are missing.

## Exclusions
Automatically ignores `node_modules`, `.git`, `dist`, and `package-lock.json` during scans to optimize performance and reduce noise.

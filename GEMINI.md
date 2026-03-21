# Check Security (GEMINI.md)

## Purpose
This MCP server provides essential security auditing tools to prevent accidental exposure of sensitive credentials and to ensure proper source control hygiene.

## Usage for Agents
- **Mandatory**: Run `scan_for_secrets` before any code is committed or shared if new files were created or modified.
- Run `check_gitignore` during the initialization of a project to ensure `.env` and other sensitive files are excluded from Git.

## Security Mandate
NEVER commit secrets. If secrets are detected, alert the user immediately and do not proceed with the commit.

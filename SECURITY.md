# Security policy

## Supported versions

Until the first stable release, security fixes are made only on the latest
published `0.0.x` release and the default branch.

## Reporting a vulnerability

Do not open a public issue for a vulnerability, credential exposure, scope
escape, or finding that contains target data. Use the repository's private
GitHub vulnerability-reporting form. Repository maintainers must enable this
feature before publication. Include a minimal reproducer with synthetic targets
and redacted output.

Reports should explain the affected version, expected safety boundary, actual
behavior, and whether any request reached a target outside the configured
allowlist. Never attach a real engagement run directory.

## Operational data

Sweeper output may contain target inventories, response evidence, credentials,
and authentication material. Run directories are intentionally excluded from
version control and must be handled as engagement evidence.

# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub: open this repository's Security tab and choose "Report a vulnerability". Do not open a public issue for a security problem.

Include what you found, how to reproduce it and which version or commit it affects. You can expect an acknowledgement within a few days.

## How this project is checked

Every push and pull request runs the [Security Software Factory](https://github.com/AakashDadhich/security-factory): secret scanning, static analysis, dependency and SBOM checks, and (for web apps) a dynamic scan. A pull request cannot merge while the `factory / gate` check is red.

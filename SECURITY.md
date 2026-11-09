# Security policy

pr-sentinel scores authentication logs. A bug in scoring can hide an attack or
flood an operator with false alerts. Treat reports accordingly.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub Security Advisories:

<https://github.com/Matt-mdlivingston/pr-sentinel/security/advisories/new>

Do not open a public issue for a security report, and do not include exploit
details in a pull request.

Include, when you can:

- the version or commit you tested
- the rules file, if a non-default policy is required to reproduce the bug
- a minimal synthetic event sequence (no production logs, no real addresses of
  real people)

## What to expect

We will acknowledge a report within a few days, confirm or reject it, and
coordinate a fix before any public write-up. There is no bug-bounty program.

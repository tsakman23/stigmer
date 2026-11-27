# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately, not in a public issue or pull request.

Use GitHub's private vulnerability reporting: open the [Security tab](https://github.com/tsakman23/stigmer/security) of this repository and choose "Report a vulnerability". Only the maintainer can see the report.

If that option is not available, open an issue that says you have a security report and asks for a private way to send it. Do not include any details in the issue.

A useful report says which version or commit you tested, how to reproduce the problem, and what an attacker could do with it.

## Supported versions

Stigmer is pre-1.0 and maintained by one person in their spare time. Only the latest release and the `main` branch get security fixes.

| Version | Supported |
|---|---|
| 0.2.x (latest) | yes |
| 0.1.x | no |

## What to expect

This is a personal project, so there is no guaranteed response time. I aim to acknowledge a report within a week and to tell you whether I consider it a vulnerability. Fixes for confirmed issues go into the next release, and the report is credited unless you ask otherwise.

## Scope

Local mode has no authentication by design: it listens on loopback only, and anyone who can run programs on that machine is the admin. Reports about local mode are still welcome when they let something outside the machine reach the board. The design's known gaps (for example [section 14](docs/design.md#14-m1-as-built)) are already public; a report that shows one of them is worse than described is welcome too.

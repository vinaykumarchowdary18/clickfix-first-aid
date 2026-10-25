# Security policy

ClickFix First Aid is a free safety aid, not antivirus. It recognizes known ClickFix patterns, and a new disguise can get past it. Read the limitations in [README.md](README.md).

## Reporting a bypass

If you find a ClickFix page or technique that gets past ClickFix First Aid, please report it privately first, using GitHub's **Report a vulnerability** button on the Security tab of this repository. Include:

- what the page did (how it copied the command, what it told the user to do),
- the command, **defanged** (break URLs like `hxxps[://]example[.]com`),
- your browser and version.

Please do not post working bypasses publicly until a fix is released. Never include real credentials or your PC check output.

Maintainer note: private vulnerability reporting must be switched on first: repository **Settings**, then **Advanced Security** (in the "Security and quality" section), then **Private vulnerability reporting: Enable**.

## Supported versions

Only the latest release gets fixes.

## If you were attacked

This project cannot investigate individual incidents. Follow the [recovery guide](guide/recovery.html), and report the crime to your national cybercrime service (in India: helpline 1930 or cybercrime.gov.in).

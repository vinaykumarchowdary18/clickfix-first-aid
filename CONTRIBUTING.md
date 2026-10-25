# Contributing

Thank you for helping. The most useful contributions:

1. **New attack samples.** Saw a ClickFix page that was not blocked? Add the command to `tests/fixtures/commands.json` under `block`, defanged: replace real hosts with `example.invalid`, `*.example` or an address from `203.0.113.0/24`. Then adjust `rules/clickfix-rules.json` until `npm test` and `npm run test:ps` pass.
2. **False alarms.** A normal command that got blocked? Add it under `allow` (or `hold`, if it really does download and run something) and fix the rule.
3. **Translations** of the warnings (`extension/src/ui.js`) and the recovery guide (`guide/recovery.html`).
4. **New platforms**: Firefox, a Mac version of the PC check.

## Ground rules

- Never commit live malware, real attacker URLs or working payloads. Test pages must only copy harmless commands such as `echo`.
- Rules must work in both JavaScript and .NET regular expressions (the build compiles them, the PowerShell tests run them).
- Rules must stay fast on hostile text: give every repeat an upper limit (`{1,63}`, not `+`) when it is followed by more pattern. `npm test` times every rule on 200,000 characters of unlucky input.
- Keep the PowerShell scripts plain ASCII and compatible with Windows PowerShell 5.1.
- The extension must stay free of network access.
- After editing anything in `rules/`, `engine/`, `guide/` or `checker/src/`, run `npm run build` and commit the generated files too. CI fails if they are out of date.

## Running everything

```bash
npm ci              # exact tool versions from package-lock.json
npm run build
npm test
npm run test:ps     # needs PowerShell 7 (pwsh)
npx playwright install chromium
npm run test:e2e
npm run links       # optional: checks the recovery guide's official links
```

Security bypasses go to the private "Report a vulnerability" button on the Security tab, not to a public issue. See [SECURITY.md](SECURITY.md).

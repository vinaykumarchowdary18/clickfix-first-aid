# Contributing

Thank you for helping. The most useful contributions:

1. **New attack samples.** Saw a ClickFix page that was not blocked? Add the command to `tests/fixtures/commands.json` under `block`, defanged: replace real hosts with `example.invalid`, `*.example` or an address from `203.0.113.0/24`. Then adjust `rules/clickfix-rules.json` until `npm test` and `npm run test:ps` pass.
2. **False alarms.** A normal command that got blocked? Add it under `allow` or `warn` and fix the rule.
3. **Translations** of the warnings (`extension/src/ui.js`) and the recovery guide (`guide/recovery.html`).
4. **New platforms**: Firefox, a Mac version of the PC check.

## Ground rules

- Never commit live malware, real attacker URLs or working payloads. Test pages must only copy harmless commands such as `echo`.
- Rules must work in both JavaScript and .NET regular expressions (the build compiles them, the PowerShell tests run them).
- Keep the PowerShell scripts plain ASCII and compatible with Windows PowerShell 5.1.
- The extension must stay free of network access.
- After editing anything in `rules/`, `engine/`, `guide/` or `checker/src/`, run `npm run build` and commit the generated files too. CI fails if they are out of date.

## Running everything

```bash
npm run build
npm test
npm run test:ps     # needs PowerShell 7 (pwsh)
npm run test:e2e    # needs: npm install && npx playwright install chromium
```

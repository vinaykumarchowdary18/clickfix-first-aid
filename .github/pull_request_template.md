## What changes for the person using it

## Checks

- [ ] `npm run build` and `npm run check-build`
- [ ] `npm test`, `npm run test:ps` and `npm run test:e2e` pass
- [ ] New attack shapes have a test that failed before the change; new false-positive fixes have an `allow` or `hold` test
- [ ] Test samples use only `example.invalid`, `*.example` or `203.0.113.0/24`, and harmless payloads like `echo test`
- [ ] No network access, telemetry or remote code added to the extension
- [ ] Limits and trade-offs are written down in README.md, not hidden

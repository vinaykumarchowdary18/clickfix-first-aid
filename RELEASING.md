# Releasing

## Every release

1. Update `version` in `package.json` and add a section to `CHANGELOG.md`.
2. `npm ci`, then `npm run build` and commit the generated files.
3. All of these pass: `npm run check-build`, `npm test`, `npm run test:ps`, `npm run test:e2e`, `npm audit --audit-level=moderate`.
4. `npm run package`, then run the browser tests once more against the packaged extension: unzip `dist/clickfix-first-aid-extension-vX.Y.Z.zip` and run `CFA_EXTENSION_DIR=<unzipped folder> npm run test:e2e`.
5. Push and wait for CI (Linux on Node 22 and 24, Windows PowerShell 5.1, and the Microsoft Defender scan of the repository) to pass. If the Defender job says it was skipped, Defender was not available on the runner: unzip the release on a Windows PC with Defender before calling it done.
6. Push a tag `vX.Y.Z`. The Release workflow rebuilds everything from the source on GitHub's machine, runs the tests again, and publishes the release with the files from `dist/` and their SHA-256 checksums (`SHA256SUMS.txt`).

## Before calling a release stable, or publishing to a browser store

- Try it by hand on the current Chrome and Edge on Windows, and on the oldest Chrome the manifest allows (`minimum_chrome_version`).
- Run `Check-ClickFix.ps1` on a few real Windows PCs, including one not set to English.
- Check false alarms on real developer documentation, online code editors and very large pages.
- Run `npm run links` and read any "unsure" result by hand. A 403 or 429 means the site refused an automated check, not that the page is gone.
- Read every line of the recovery guide against the official help pages again. Menus move.
- Ask for an independent review of the changes, and verify its findings before acting on them.

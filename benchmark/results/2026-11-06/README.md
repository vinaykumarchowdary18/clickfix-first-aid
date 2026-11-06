# Results, 6 November 2026

Measured with `benchmark/run.mjs` in Chromium 141.0.7390.37 (Playwright, new headless mode), one extension at a time, with its default settings unless stated. These are the results used in the [technical report](../../../report/ClickFix-First-Aid-Technical-Report.md), section 7.

| File | Tool | Version and commit tested |
|---|---|---|
| `00-none.json` | No extension (control) | |
| `01-cfa.json` | ClickFix First Aid | 0.3.3; `extension/` identical to the v0.3.3 release |
| `02-warden.json` | ClickFix Warden (xVoidByte) | see `meta` in the file |
| `03-guard-samdem.json` | ClickFix Guard (samdem-ai) | see `meta` |
| `04-stopfix.json` | StopFix (naxonez) | see `meta` |
| `05-guard-frameman.json` | ClickFix Guard (frameman) | see `meta` |
| `06-guard-samurayski.json` | ClickFix Guard (samurayski) | see `meta` |
| `07-mitigator.json` | ClickFix Mitigator (j0rd1s3rr4n0) | see `meta` |
| `08-mitigator-blockall-off.json` | ClickFix Mitigator with "Block all JavaScript clipboard copying" switched off (`--storage '{"blockAllClipboard":false}'`) | see `meta` |

Each file has `meta` (tool, version, commit, browser, date, timing), `summary` (counts per scenario) and `results` (one entry per case). The final run waited 1 second between a page loading and the click (`--think 1000`) and 5 seconds after the click (`--wait 5000`).

`screenshots/` has a screenshot of the page 5 seconds after the click for three cases per tool: an attack on a fake verification page (`attack-lure-H17`), the same attack on a page without instructions (`attack-plain-H17`), and an official installer one-liner (`benign-B01`).

`first-run-no-pause/` has an earlier run of the same samples that clicked as soon as each page had loaded (before `--think` existed). Two tools behaved differently in it, ClickFix Mitigator and ClickFix Guard (frameman); the report explains why the final run uses the pause.

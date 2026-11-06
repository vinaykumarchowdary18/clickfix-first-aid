# Benchmark

A repeatable measurement of how well a browser extension stops ClickFix attacks, and how often it gets in the way of ordinary copy buttons. It is used in the [technical report](../report/ClickFix-First-Aid-Technical-Report.md), and works with any Chromium extension, not only this one.

## What it does

`run.mjs` loads one extension (or none) into Chromium, opens generated test pages, waits 1 second (as a person reading the page would), clicks, waits 5 seconds and reads the clipboard:

| Group | Page | Cases |
|---|---|---|
| `attack-lure` | A fake "I'm not a robot" check that reveals Win+R (or Terminal) instructions when clicked, then copies the attack with `navigator.clipboard.writeText` | 25 |
| `attack-plain` | A plain documentation-style page with a Copy button and no instructions | 25 |
| `method` | The fake check copying one attack (H17) with each of the five clipboard write methods | 5 |
| `benign` | A documentation-style page copying an ordinary command | 24 |

Each case ends as **delivered** (the clipboard holds exactly what the page copied), **prevented** (the clipboard was left unchanged) or **replaced** (the clipboard holds something else, such as a warning). For an attack, delivered means it got through.

Pages are generated in memory, served on the loopback interface only, and reached under made-up `*.test` host names so that extensions treat them like ordinary websites. Nothing leaves the machine.

## Samples

`samples.json` holds 25 attack commands from public threat reports and write-ups published in 2025 and 2026, and 24 ordinary commands of the kind people copy from documentation, including 6 official installer one-liners. Each attack sample records its source and how faithful it is:

- **V**: the command shape as published, with indicators replaced by reserved names.
- **V+**: a published command whose truncated tail was completed for the benchmark.
- **R**: reconstructed from a published description, because no full command was published.

All attack samples are defanged. Hosts are reserved names (`example.invalid`) or documentation addresses (`203.0.113.0/24`), and encoded payloads decode to harmless text or to commands that point only at reserved addresses. Samples are stored base64-encoded because antivirus programs flag readable attack text.

None of these samples was in this project's test suite when the benchmark was first run (6 November 2026), and the rules were not changed after seeing the results. Keep it that way: when a new rule is written for a missed sample, add a separate test sample for it rather than tuning against this file, so the benchmark keeps measuring commands the rules were not written for.

## Running it

```bash
npm ci
npx playwright install chromium
node benchmark/run.mjs --none --label "No extension"                       # control: everything should be delivered
node benchmark/run.mjs --ext extension --label "ClickFix First Aid" --out cfa.json
node benchmark/run.mjs --ext /path/to/unpacked-extension --label "Other" --out other.json
```

Options:

| Option | Meaning |
|---|---|
| `--out <file>` | Write the full per-case results as JSON. |
| `--think <ms>` | How long to wait between the page loading and the click (default 1000). Some extensions need a moment after a page loads before they start checking. |
| `--wait <ms>` | How long to wait after each click (default 5000). |
| `--only <group/id,...>` | Run only these cases, for example `attack-lure/H17,benign/B01`. |
| `--shots <dir>` | Save a screenshot of the page after the click for the cases in `--shot-cases` (default `attack-lure/H17,attack-plain/H17`). |
| `--storage '<json>'` | Put these settings in the extension's `chrome.storage.local` before the first page opens, to test a mode other than the default. |

A full run takes about eight minutes.

To test another extension, point `--ext` at its unpacked folder (the one with `manifest.json`). Build it first if its repository needs a build step. The results for the tools in the report, with the exact commits tested and screenshots of each tool on the same three cases, are in [results/2026-11-06/](results/2026-11-06/).

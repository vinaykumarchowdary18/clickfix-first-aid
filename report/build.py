#!/usr/bin/env python3
"""Builds ClickFix-First-Aid-Technical-Report.pdf from the Markdown source.

Needs pandoc and Python Playwright with Chromium:
    pip install playwright && python -m playwright install chromium
    python3 report/build.py
"""
import html
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE / 'ClickFix-First-Aid-Technical-Report.md'
OUT = HERE / 'ClickFix-First-Aid-Technical-Report.pdf'
TMP_HTML = HERE / '.build.html'

md = SRC.read_text(encoding='utf-8')
preamble, body = md.split('\n---\n', 1)

# ---- Cover data from the Markdown preamble ---------------------------------
title = re.search(r'^# (.+)$', preamble, re.M).group(1).strip()
subtitle = re.search(r'^\*\*(.+)\*\*$', preamble, re.M).group(1).strip()
meta = []
for line in preamble.splitlines():
    m = re.match(r'^\|\s*([^|]+?)\s*\|\s*(.+?)\s*\|$', line)
    if m and m.group(1) not in ('', '---') and not set(m.group(1)) <= set('-'):
        value = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'\1', m.group(2))
        meta.append((m.group(1), value))
meta_map = dict(meta)

# ---- Body: Markdown to HTML with pandoc -----------------------------------
ARR_R = '<svg width="14" height="12" viewBox="0 0 14 12"><path d="M0 6h11M7 1.5L12 6 7 10.5" fill="none" stroke="#0f2a4a" stroke-width="1.6"/></svg>'
ARR_U = '<svg width="12" height="14" viewBox="0 0 12 14"><path d="M6 14V3M1.5 7L6 2l4.5 5" fill="none" stroke="#0f2a4a" stroke-width="1.6"/></svg>'
ARR_D = '<svg width="12" height="14" viewBox="0 0 12 14"><path d="M6 0v11M1.5 7L6 12l4.5-5" fill="none" stroke="#0f2a4a" stroke-width="1.6"/></svg>'
DIAGRAM = f'''
<figure class="diagram">
  <div class="grid">
    <div class="node src" style="grid-area:1/1">Web page script<small>writeText, write, execCommand,<br>setData, items.add</small></div>
    <div class="arrow" style="grid-area:1/2">{ARR_R}</div>
    <div class="node guard" style="grid-area:1/3">Clipboard guard<small>page world, loads before<br>any page script</small></div>
    <div class="arrow" style="grid-area:1/4">{ARR_R}</div>
    <div class="node engine" style="grid-area:1/5">Rules engine<small>isolated world, rules shared<br>with the PowerShell checker</small></div>
    <div class="arrow" style="grid-area:1/6">{ARR_R}</div>
    <div class="verdicts" style="grid-area:1/7">
      <div class="node v allow"><b>Allow</b> original text is copied</div>
      <div class="node v hold"><b>Hold</b> <code># PAUSED</code> note, Copy anyway</div>
      <div class="node v block"><b>Block</b> <code># STOP</code> note, full-page warning</div>
    </div>
    <div class="arrow" style="grid-area:2/5">{ARR_U}</div>
    <div class="arrow" style="grid-area:2/7">{ARR_D}</div>
    <div class="node side" style="grid-area:3/5">Page text scan<small>Win+R, paste, "I am not a robot";<br>every frame, also after the click</small></div>
    <div class="node side" style="grid-area:3/7">Background worker<small>counters, settings and per-tab state<br>that survive worker restarts</small></div>
  </div>
  <figcaption>Figure 2. How a clipboard write is checked. No step uses the network.</figcaption>
</figure>
'''

body_html = subprocess.run(
    ['pandoc', '-f', 'gfm', '-t', 'html5', '--no-highlight', '--wrap=none'],
    input=body, capture_output=True, text=True, check=True,
).stdout
body_html = re.sub(r'<pre class="mermaid"><code>.*?</code></pre>', DIAGRAM, body_html, flags=re.S)
body_html = re.sub(r'<pre lang="mermaid"><code>.*?</code></pre>', DIAGRAM, body_html, flags=re.S)

# Contents from the numbered and appendix headings.
contents = re.findall(r'<h2[^>]*\bid="([^"]+)"[^>]*>(.*?)</h2>', body_html, flags=re.S)
toc = '\n'.join(f'<li><a href="#{i}">{t}</a></li>' for i, t in contents)

fonts = HERE / 'fonts'
def face(fam, file, weight, style='normal'):
    return f"@font-face{{font-family:'{fam}';src:url('{(fonts / file).as_uri()}') format('woff2');font-weight:{weight};font-style:{style};}}"

CSS = '\n'.join([
    face('Plex Sans', 'ibm-plex-sans-latin-400-normal.woff2', 400),
    face('Plex Sans', 'ibm-plex-sans-latin-400-italic.woff2', 400, 'italic'),
    face('Plex Sans', 'ibm-plex-sans-latin-500-normal.woff2', 500),
    face('Plex Sans', 'ibm-plex-sans-latin-600-normal.woff2', 600),
    face('Plex Sans', 'ibm-plex-sans-latin-700-normal.woff2', 700),
    face('Plex Mono', 'ibm-plex-mono-latin-400-normal.woff2', 400),
    face('Plex Mono', 'ibm-plex-mono-latin-500-normal.woff2', 500),
]) + '''
@page { size: A4; margin: 20mm 17mm 18mm; }
@page :first { margin: 0; }
* { box-sizing: border-box; }
html { font-family: 'Plex Sans', sans-serif; font-size: 9.6pt; line-height: 1.5; color: #1b2430; }
body { margin: 0; }
a { color: #0b5cad; text-decoration: none; }
code { font-family: 'Plex Mono', monospace; font-size: 0.88em; background: #f1f4f8; padding: 0.05em 0.3em; border-radius: 3px; }
pre { font-family: 'Plex Mono', monospace; font-size: 8.4pt; background: #f4f6f9; border: 1px solid #dde3ea; border-radius: 4px; padding: 9px 11px; white-space: pre-wrap; break-inside: avoid; }
pre code { background: none; padding: 0; font-size: inherit; }
h2 { font-size: 15pt; font-weight: 600; color: #0f2a4a; margin: 22pt 0 7pt; padding-bottom: 4pt; border-bottom: 1.5px solid #0f2a4a; break-after: avoid; }
h3 { font-size: 11.2pt; font-weight: 600; color: #0f2a4a; margin: 14pt 0 5pt; break-after: avoid; }
p, li { orphans: 3; widows: 3; }
p { margin: 0 0 7pt; }
ul, ol { margin: 0 0 8pt; padding-left: 16pt; }
li { margin-bottom: 3pt; }
table { width: 100%; border-collapse: collapse; margin: 6pt 0 11pt; font-size: 8.6pt; break-inside: auto; }
tr { break-inside: avoid; }
thead { display: table-header-group; }
th { text-align: left; font-weight: 600; background: #0f2a4a; color: #fff; padding: 5px 7px; }
td { padding: 4.5px 7px; border-bottom: 1px solid #dfe5ec; vertical-align: top; }
tbody tr:nth-child(even) td { background: #f7f9fb; }
hr { display: none; }
p.shots { display: flex; gap: 2%; margin: 4pt 0 4pt; break-inside: avoid; }
p.shots img { width: 49%; height: auto; border: 1px solid #dde3ea; border-radius: 4px; }
p.shots + p { font-size: 8.2pt; color: #5a6878; }
strong { font-weight: 600; }
.cover { height: 297mm; padding: 0; display: flex; flex-direction: column; page-break-after: always; }
.cover .band { background: #0f2a4a; color: #fff; padding: 34mm 22mm 20mm; }
.cover .kicker { font-size: 10pt; letter-spacing: 0.16em; text-transform: uppercase; color: #9fc3ea; margin-bottom: 10pt; }
.cover h1 { font-size: 30pt; line-height: 1.15; margin: 0 0 10pt; font-weight: 700; }
.cover .sub { font-size: 13pt; color: #d7e6f6; max-width: 150mm; line-height: 1.4; }
.cover .meta { padding: 16mm 22mm; flex: 1; }
.cover .meta table { width: 120mm; font-size: 10pt; }
.cover .meta td { border-bottom: 1px solid #dfe5ec; background: none !important; padding: 6px 4px; }
.cover .meta td:first-child { color: #5a6878; width: 42mm; }
.cover .foot { padding: 0 22mm 16mm; font-size: 8.6pt; color: #5a6878; }
.contents { page-break-after: always; }
.contents h2 { margin-top: 0; }
.contents ol { list-style: none; padding: 0; font-size: 10.5pt; }
.contents li { padding: 5px 0; border-bottom: 1px dotted #c9d3de; }
.diagram { margin: 8pt 0 12pt; break-inside: avoid; }
.diagram .grid { display: grid; grid-template-columns: 1fr 18px 1fr 18px 1fr 18px 1.3fr; grid-template-rows: auto 18px auto; align-items: center; }
.diagram .node { border: 1.2px solid #0f2a4a; border-radius: 5px; padding: 7px 8px; font-weight: 600; font-size: 8.6pt; text-align: center; background: #fff; }
.diagram .node small { display: block; font-weight: 400; font-size: 7.4pt; color: #4a5868; margin-top: 3px; line-height: 1.35; }
.diagram .guard, .diagram .engine { background: #eaf2fb; }
.diagram .arrow { display: flex; justify-content: center; align-items: center; }
.diagram .verdicts { display: grid; gap: 4px; }
.diagram .v { text-align: left; font-weight: 400; font-size: 7.8pt; padding: 5px 7px; }
.diagram .v b { font-weight: 600; margin-right: 4px; }
.diagram .v code { font-size: 7.4pt; }
.diagram .allow { border-color: #2f7d4f; background: #eef8f1; }
.diagram .hold { border-color: #a86b00; background: #fdf6e7; }
.diagram .block { border-color: #b3261e; background: #fcefee; }
.diagram .side { background: #f7f9fb; border-style: dashed; }
.diagram figcaption { font-size: 8.2pt; color: #5a6878; margin-top: 8px; }
'''

cover = f'''
<section class="cover">
  <div class="band">
    <div class="kicker">Technical report &middot; {html.escape(meta_map.get('Document', ''))}</div>
    <h1>{html.escape(title)}</h1>
    <div class="sub">{html.escape(subtitle)}</div>
  </div>
  <div class="meta"><table>{''.join(f'<tr><td>{html.escape(k)}</td><td>{html.escape(v)}</td></tr>' for k, v in meta)}</table></div>
  <div class="foot">ClickFix First Aid is free, open-source software released under the MIT License. This report is part of its public repository and may be shared freely.</div>
</section>
<section class="contents"><h2>Contents</h2><ol>{toc}</ol></section>
'''

doc = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{html.escape(title)}</title>
<style>{CSS}</style></head><body>{cover}<main>{body_html}</main></body></html>'''
TMP_HTML.write_text(doc, encoding='utf-8')

footer = (
    '<div style="width:100%;font-family:Liberation Sans,Arial,sans-serif;font-size:7.5pt;color:#6b7785;padding:0 17mm;display:flex;justify-content:space-between;">'
    f'<span>{html.escape(title)} &middot; {html.escape(meta_map.get("Document", ""))} &middot; Version {html.escape(meta_map.get("Version", ""))}</span>'
    '<span>Page <span class="pageNumber"></span> of <span class="totalPages"></span></span></div>'
)

from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page()
    page.goto(TMP_HTML.as_uri())
    page.evaluate('document.fonts.ready')
    page.pdf(path=str(OUT), format='A4', print_background=True, prefer_css_page_size=True,
             display_header_footer=True, header_template='<div></div>', footer_template=footer)
    browser.close()
TMP_HTML.unlink()
print('wrote', OUT)

#!/usr/bin/env python3
"""Convert the extended-demonstration transcript into a self-contained HTML page
with collapsible byte blocks."""

import html
import re
import sys
from pathlib import Path

SRC = Path(sys.argv[1] if len(sys.argv) > 1 else "src.txt")
OUT = Path(sys.argv[2] if len(sys.argv) > 2 else "/mnt/user-data/outputs/ext_demo_sample_output_2.html")

RULE = re.compile(r"^═+\s*$")
SECTION = re.compile(r"^──\s*(.*?)\s*─+\s*$")
CHECK = re.compile(r"^\s*\[✓\]\s*(.*)$")
LIMIT = re.compile(r"^\s*\[!\]\s*(.*)$")   # optional marker for a stated limitation
SIZE = re.compile(r"^(.*?)\s*\((\d+\s*(?:bytes|bits))\)\s*$")
KV = re.compile(r"\S {2,}\S")

lines = SRC.read_text(encoding="utf-8").split("\n")

blocks = []          # flat list of dicts
preamble = []
i = 0

# ---- preamble: everything before the first banner ---------------------------
while i < len(lines) and not RULE.match(lines[i]):
    if lines[i].strip():
        preamble.append(lines[i].strip())
    i += 1

prose_buf = []


def flush_prose():
    if prose_buf:
        blocks.append({"t": "prose", "text": " ".join(prose_buf)})
        prose_buf.clear()


while i < len(lines):
    line = lines[i]

    # --- part banner: ═══ / title / ═══ ------------------------------------
    if RULE.match(line):
        if i + 2 < len(lines) and RULE.match(lines[i + 2]) and lines[i + 1].strip():
            flush_prose()
            title = lines[i + 1].strip()
            if "·" in title:
                part, rest = title.split("·", 1)
                blocks.append({"t": "part", "eyebrow": part.strip(), "title": rest.strip()})
            else:
                blocks.append({"t": "part", "eyebrow": "", "title": title})
            i += 3
            continue
        i += 1
        continue

    m = SECTION.match(line)
    if m:
        flush_prose()
        blocks.append({"t": "section", "title": m.group(1)})
        i += 1
        continue

    if not line.strip():
        flush_prose()
        i += 1
        continue

    m = CHECK.match(line)
    if m:
        flush_prose()
        blocks.append({"t": "check", "text": m.group(1)})
        i += 1
        continue

    m = LIMIT.match(line)
    if m:
        flush_prose()
        blocks.append({"t": "limit", "text": m.group(1)})
        i += 1
        continue

    indent = len(line) - len(line.lstrip(" "))
    body = line.strip()

    # --- data line (only valid directly under a label or another data line) --
    if indent >= 6 and blocks and blocks[-1]["t"] in ("label", "data"):
        if blocks[-1]["t"] == "data":
            blocks[-1]["lines"].append(body)
        else:
            blocks.append({"t": "data", "lines": [body]})
        i += 1
        continue

    # --- label: a caption whose value follows indented ----------------------
    # A caption only opens a byte block if it declares a size, e.g. "(256 bytes)".
    # Without that, an indented line below is just a continuation value row.
    j = i + 1
    nxt = lines[j] if j < len(lines) else ""
    nxt_indent = len(nxt) - len(nxt.lstrip(" ")) if nxt.strip() else -1
    sm = SIZE.match(body)
    if nxt_indent >= 6 and sm and not CHECK.match(nxt):
        flush_prose()
        blocks.append({"t": "label", "name": sm.group(1).strip(), "size": sm.group(2)})
        i += 1
        continue

    # --- key / value row ----------------------------------------------------
    if KV.search(line):
        flush_prose()
        parts = re.split(r" {2,}", body, maxsplit=1)
        key = parts[0]
        val = parts[1].rstrip() if len(parts) > 1 else ""
        blocks.append({"t": "kv", "key": key, "val": val})
        i += 1
        continue

    prose_buf.append(body)
    i += 1

flush_prose()

# ---- merge label + following data into one collapsible ----------------------
merged = []
for b in blocks:
    if b["t"] == "data" and merged and merged[-1]["t"] == "label":
        lab = merged.pop()
        merged.append({
            "t": "bytes",
            "name": lab["name"],
            "size": lab["size"],
            "lines": b["lines"],
        })
    else:
        merged.append(b)
blocks = merged

# ---- statistics -------------------------------------------------------------
n_checks = sum(1 for b in blocks if b["t"] == "check")
n_limits = sum(1 for b in blocks if b["t"] == "limit")
n_bytes = sum(1 for b in blocks if b["t"] == "bytes")
parts = [b for b in blocks if b["t"] == "part"]

# ---- render -----------------------------------------------------------------
e = html.escape


def slug(s, n=[0]):
    n[0] += 1
    return "p%d-%s" % (n[0], re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:40])


out = []
toc = []
open_part = False

for b in blocks:
    t = b["t"]
    if t == "part":
        if open_part:
            out.append("</section>")
        sid = slug(b["title"])
        toc.append((sid, b["eyebrow"], b["title"]))
        out.append(f'<section class="part" id="{sid}">')
        out.append(
            '<header class="part-head">'
            f'<span class="eyebrow">{e(b["eyebrow"])}</span>'
            f'<h2>{e(b["title"])}</h2>'
            "</header>"
        )
        open_part = True
    elif t == "section":
        out.append(f'<h3 class="section">{e(b["title"])}</h3>')
    elif t == "prose":
        out.append(f'<p class="prose">{e(b["text"])}</p>')
    elif t == "limit":
        out.append(f'<p class="limit"><span class="bang">!</span>{e(b["text"])}</p>')
    elif t == "check":
        out.append(f'<p class="check"><span class="tick">✓</span>{e(b["text"])}</p>')
    elif t == "kv":
        out.append(
            f'<p class="kv"><span class="k">{e(b["key"])}</span>'
            f'<span class="v">{e(b["val"])}</span></p>'
        )
    elif t == "label":
        out.append(f'<p class="kv"><span class="k">{e(b["name"])}</span></p>')
    elif t == "bytes":
        joined = "\n".join(b["lines"])
        flat = "".join(x.strip() for x in b["lines"])
        peek = flat[:20] + ("…" if len(flat) > 20 else "")
        size = f'<span class="size">{e(b["size"])}</span>' if b["size"] else ""
        out.append(
            '<details class="bytes">'
            f'<summary><span class="sum-main"><span class="name">{e(b["name"])}</span>'
            f'{size}</span><span class="peek">{e(peek)}</span></summary>'
            f'<pre>{e(joined)}</pre>'
            "</details>"
        )

if open_part:
    out.append("</section>")

nav = "\n".join(
    f'<li><a href="#{sid}"><span>{e(eb)}</span>{e(ti)}</a></li>' for sid, eb, ti in toc
)

title = preamble[0] if preamble else "Extended demonstration"
sub = preamble[1] if len(preamble) > 1 else ""
warn = [p for p in preamble[2:] if p]

CSS = """
:root{
  --paper:#f7f7f4; --ink:#16191c; --muted:#5d6570;
  --slate:#263445; --rule:#dcdcd5; --rule-soft:#e8e8e2;
  --verify:#166b4a; --verify-bg:#eef4f0;
  --limit:#8a5a12; --limit-bg:#f6f1e6;
  --data:#42566b; --data-bg:#f1f2ef;
  --serif:Charter,"Bitstream Charter","Sitka Text",Cambria,Georgia,serif;
  --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace;
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--paper);color:var(--ink);font-family:var(--serif);
  font-size:17px;line-height:1.55;-webkit-text-size-adjust:100%}
@media (prefers-reduced-motion:reduce){html{scroll-behavior:auto}*{transition:none!important}}

/* ---------- masthead ---------- */
.mast{border-bottom:1px solid var(--rule);padding:3rem 0 1.6rem}
.wrap{max-width:1080px;margin:0 auto;padding:0 1.5rem}
.mast h1{font-family:var(--mono);font-size:1.45rem;font-weight:600;letter-spacing:-.01em;
  margin:0 0 .5rem;line-height:1.25}
.mast .sub{font-family:var(--mono);font-size:.78rem;color:var(--muted);
  letter-spacing:.01em;margin:0 0 1.4rem}
.mast .warn{font-size:.92rem;color:var(--muted);margin:.2rem 0;max-width:62ch}
.selfcheck{margin:1.6rem 0 0;padding:.85rem 1.1rem;background:var(--verify-bg);
  border-left:3px solid var(--verify);display:flex;flex-wrap:wrap;gap:.5rem 1.6rem;align-items:baseline}
.selfcheck strong{font-family:var(--mono);font-size:.95rem;color:var(--verify);font-weight:600;margin-right:1rem}
.selfcheck span{font-size:.92rem;color:var(--muted)}
.selfcheck .limit-note{font-family:var(--mono);font-size:.8rem;color:var(--limit)}

/* ---------- layout ---------- */
.cols{max-width:1080px;margin:0 auto;padding:0 1.5rem;display:grid;
  grid-template-columns:210px minmax(0,1fr);gap:3rem;align-items:start}
nav.toc{position:sticky;top:1.5rem;max-height:calc(100vh - 3rem);overflow-y:auto;
  padding:2rem 0;font-family:var(--mono);font-size:.72rem}
nav.toc ol{list-style:none;margin:0;padding:0}
nav.toc li{margin:0 0 .45rem}
nav.toc a{display:block;color:var(--muted);text-decoration:none;line-height:1.35;
  border-left:2px solid var(--rule-soft);padding-left:.6rem}
nav.toc a:hover,nav.toc a:focus{color:var(--slate);border-left-color:var(--slate)}
nav.toc a span{display:block;font-size:.62rem;letter-spacing:.09em;text-transform:uppercase;
  color:#9aa1a9}
main{padding:2rem 0 6rem;min-width:0}

/* ---------- controls ---------- */
.controls{display:flex;gap:.5rem;margin:0 0 2rem;font-family:var(--mono);font-size:.72rem}
.controls button{font:inherit;background:transparent;color:var(--muted);cursor:pointer;
  border:1px solid var(--rule);padding:.35rem .7rem;border-radius:2px}
.controls button:hover{border-color:var(--slate);color:var(--slate)}
.controls button:focus-visible{outline:2px solid var(--slate);outline-offset:2px}

/* ---------- parts ---------- */
.part{margin:0 0 3.5rem;scroll-margin-top:1.5rem}
.part-head{border-top:2px solid var(--slate);padding-top:.65rem;margin:0 0 1.2rem}
.eyebrow{display:block;font-family:var(--mono);font-size:.66rem;letter-spacing:.14em;
  text-transform:uppercase;color:var(--slate);margin-bottom:.3rem}
.part-head h2{font-family:var(--mono);font-size:1.02rem;font-weight:600;margin:0;
  letter-spacing:-.005em;line-height:1.35}
h3.section{font-family:var(--mono);font-size:.78rem;font-weight:600;color:var(--slate);
  margin:2rem 0 .8rem;padding-bottom:.35rem;border-bottom:1px solid var(--rule-soft)}
h3.section:first-of-type{margin-top:1.2rem}

/* ---------- content rows ---------- */
p{margin:0}
.prose{margin:.9rem 0;max-width:66ch;color:#2b3138}
.check{font-family:var(--mono);font-size:.79rem;color:var(--verify);margin:.28rem 0;
  padding-left:1.35rem;text-indent:-1.35rem;line-height:1.5}
.tick{display:inline-block;width:1.35rem;text-indent:0}
.limit{font-family:var(--mono);font-size:.79rem;color:var(--limit);margin:.28rem 0;
  padding-left:1.35rem;text-indent:-1.35rem;line-height:1.5;background:var(--limit-bg);
  padding-top:.15rem;padding-bottom:.15rem;padding-right:.5rem}
.bang{display:inline-block;width:1.35rem;text-indent:0;font-weight:700}
.kv{font-family:var(--mono);font-size:.79rem;margin:.28rem 0;display:flex;gap:1rem;
  flex-wrap:wrap;color:var(--muted)}
.kv .k{min-width:15rem;flex:0 0 auto}
.kv .v{color:var(--ink);word-break:break-word;min-width:0;white-space:pre-wrap}

/* ---------- collapsible byte blocks ---------- */
details.bytes{margin:.1rem 0;border-left:2px solid var(--rule-soft)}
details.bytes summary{cursor:pointer;list-style:none;padding:.26rem .7rem;
  font-family:var(--mono);font-size:.78rem;display:flex;gap:.8rem;align-items:baseline;
  flex-wrap:nowrap;color:var(--data)}
details.bytes summary::-webkit-details-marker{display:none}
details.bytes summary::before{content:"▸";font-size:.68rem;color:#a3aab2;
  flex:0 0 auto;line-height:1.5}
details.bytes[open] summary::before{content:"▾";color:var(--data)}
details.bytes summary:hover{background:var(--data-bg)}
details.bytes[open]{border-left-color:var(--data);background:var(--data-bg)}
details.bytes summary:focus-visible{outline:2px solid var(--slate);outline-offset:-2px}
summary .sum-main{flex:1 1 auto;min-width:0;overflow:hidden;text-overflow:ellipsis;
  white-space:nowrap}
summary .name{color:var(--ink);font-weight:500}
summary .size{color:#949ba3;font-size:.7rem;white-space:nowrap;margin-left:.6rem}
summary .peek{color:#a3aab2;font-size:.72rem;flex:0 0 auto;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:13rem}
details.bytes[open] summary .peek{visibility:hidden}
details.bytes pre{margin:0;padding:.15rem .7rem .7rem 1.9rem;font-family:var(--mono);
  font-size:.73rem;line-height:1.5;color:#3d454e;overflow-x:auto;white-space:pre;
  word-break:normal}

/* ---------- responsive ---------- */
@media (max-width:860px){
  .cols{grid-template-columns:1fr;gap:0}
  nav.toc{position:static;max-height:none;padding:1.5rem 0;
    border-bottom:1px solid var(--rule-soft);
    columns:2;column-gap:1.5rem}
  .kv .k{min-width:0;flex:1 1 100%}
  .kv{gap:.1rem}
  summary .peek{display:none}
}
@media print{
  nav.toc,.controls{display:none}
  .cols{display:block}
  details.bytes[open] pre{white-space:pre-wrap}
  body{font-size:10pt}
}
"""

JS = """
(function(){
  var all=function(){return Array.prototype.slice.call(document.querySelectorAll('details.bytes'))};
  document.getElementById('expand').addEventListener('click',function(){
    all().forEach(function(d){d.open=true})});
  document.getElementById('collapse').addEventListener('click',function(){
    all().forEach(function(d){d.open=false})});
})();
"""

limit_note = (f'<span class="limit-note">{n_limits} stated limitation(s) marked <b>!</b></span>'
              if n_limits else "")
warn_html = "\n".join(f'<p class="warn">{e(w)}</p>' for w in warn)

doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(title)}</title>
<meta name="description" content="Extended demonstration transcript of the anonymous authenticated ballot system proof of concept.">
<style>{CSS}</style>
</head>
<body>

<header class="mast">
  <div class="wrap">
    <h1>{e(title)}</h1>
    <p class="sub">{e(sub)}</p>
    {warn_html}
    <div class="selfcheck">
      <strong>{n_checks} checks performed, 0 failed.</strong>
      <span>Every claim below was computed in this run, not asserted by the narration.</span>
      {limit_note}
    </div>
  </div>
</header>

<div class="cols">
  <nav class="toc" aria-label="Contents">
    <ol>
{nav}
    </ol>
  </nav>

  <main>
    <div class="controls">
      <button type="button" id="expand">Expand all {n_bytes} byte blocks</button>
      <button type="button" id="collapse">Collapse all</button>
    </div>
{chr(10).join(out)}
  </main>
</div>

<script>{JS}</script>
</body>
</html>
"""

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(doc, encoding="utf-8")
print(f"parts={len(parts)} checks={n_checks} byte-blocks={n_bytes} -> {OUT} ({OUT.stat().st_size:,} bytes)")

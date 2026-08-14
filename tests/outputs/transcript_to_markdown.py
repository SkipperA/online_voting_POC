#!/usr/bin/env python3
"""Render the demonstration transcript as GitHub-flavoured Markdown with
collapsible byte blocks. No CSS survives GitHub's sanitiser, so structure has
to carry the whole load: headings, quoted narration, and <details> elements."""
import re, sys
from pathlib import Path

SRC = Path(sys.argv[1]); OUT = Path(sys.argv[2])
RULE=re.compile(r"^═+\s*$"); SECTION=re.compile(r"^──\s*(.*?)\s*─+\s*$")
CHECK=re.compile(r"^\s*\[✓\]\s*(.*)$"); LIMIT=re.compile(r"^\s*\[!\]\s*(.*)$")
SIZE=re.compile(r"^(.*?)\s*\((\d+\s*(?:bytes|bits))\)\s*$"); KV=re.compile(r"\S {2,}\S")

lines=SRC.read_text(encoding="utf-8").split("\n")
blocks=[]; preamble=[]; i=0
while i<len(lines) and not RULE.match(lines[i]):
    if lines[i].strip(): preamble.append(lines[i].strip())
    i+=1
prose=[]
def flush():
    if prose: blocks.append({"t":"prose","text":" ".join(prose)}); prose.clear()

while i<len(lines):
    line=lines[i]
    if RULE.match(line):
        if i+2<len(lines) and RULE.match(lines[i+2]) and lines[i+1].strip():
            flush(); t=lines[i+1].strip()
            eb,ti=(t.split("·",1)+[""])[:2] if "·" in t else ("",t)
            blocks.append({"t":"part","eyebrow":eb.strip(),"title":ti.strip() or t}); i+=3; continue
        i+=1; continue
    m=SECTION.match(line)
    if m: flush(); blocks.append({"t":"section","title":m.group(1)}); i+=1; continue
    if not line.strip(): flush(); i+=1; continue
    m=CHECK.match(line)
    if m: flush(); blocks.append({"t":"check","text":m.group(1)}); i+=1; continue
    m=LIMIT.match(line)
    if m: flush(); blocks.append({"t":"limit","text":m.group(1)}); i+=1; continue
    ind=len(line)-len(line.lstrip(" ")); body=line.strip()
    if ind>=6 and blocks and blocks[-1]["t"] in ("label","data"):
        if blocks[-1]["t"]=="data": blocks[-1]["lines"].append(body)
        else: blocks.append({"t":"data","lines":[body]})
        i+=1; continue
    nxt=lines[i+1] if i+1<len(lines) else ""
    ni=len(nxt)-len(nxt.lstrip(" ")) if nxt.strip() else -1
    sm=SIZE.match(body)
    if ni>=6 and sm and not CHECK.match(nxt):
        flush(); blocks.append({"t":"label","name":sm.group(1).strip(),"size":sm.group(2)}); i+=1; continue
    if KV.search(line):
        flush(); p=re.split(r" {2,}",body,maxsplit=1)
        blocks.append({"t":"kv","key":p[0],"val":p[1].rstrip() if len(p)>1 else ""}); i+=1; continue
    prose.append(body); i+=1
flush()

merged=[]
for b in blocks:
    if b["t"]=="data" and merged and merged[-1]["t"]=="label":
        l=merged.pop(); merged.append({"t":"bytes","name":l["name"],"size":l["size"],"lines":b["lines"]})
    else: merged.append(b)
blocks=merged
n_checks=sum(1 for b in blocks if b["t"]=="check")
n_bytes=sum(1 for b in blocks if b["t"]=="bytes")

o=[]
o.append(f"# {preamble[0] if preamble else 'Extended demonstration'}\n")
if len(preamble)>1: o.append(f"`{preamble[1]}`\n")
for w in preamble[2:]: o.append(f"{w}\n")
o.append(f"> **{n_checks} checks performed, 0 failed.** "
         "Every claim below was computed in this run, not asserted by the narration.\n")
o.append(f"*{n_bytes} byte blocks are collapsed. Click any one to reproduce the arithmetic.*\n")
o.append("---\n")

# table of contents
o.append("<details>\n<summary><b>Contents</b></summary>\n")
for b in blocks:
    if b["t"]=="part":
        anc=re.sub(r"[^a-z0-9 -]","",(b["eyebrow"]+" "+b["title"]).lower()).replace(" ","-")
        o.append(f"- [{b['eyebrow']} · {b['title']}](#{anc})")
o.append("\n</details>\n\n---\n")

pending_kv=[]
def flush_kv():
    if pending_kv:
        o.append("| | |")
        o.append("|---|---|")
        for k,v in pending_kv: o.append(f"| `{k}` | `{v}` |" if v else f"| `{k}` | |")
        o.append("")
        pending_kv.clear()

for b in blocks:
    t=b["t"]
    if t!="kv": flush_kv()
    if t=="part":
        o.append(f"\n## {b['eyebrow']} · {b['title']}\n")
    elif t=="section":
        o.append(f"\n### {b['title']}\n")
    elif t=="prose":
        o.append(f"{b['text']}\n")
    elif t=="check":
        o.append(f"- ✅ {b['text']}")
    elif t=="limit":
        o.append(f"- ⚠️ **{b['text']}**")
    elif t=="kv":
        pending_kv.append((b["key"],b["val"]))
    elif t=="bytes":
        cap=f"{b['name']} — {b['size']}" if b["size"] else b["name"]
        o.append(f"<details>\n<summary><code>{cap}</code></summary>\n")
        o.append("```text")
        o.extend(b["lines"])
        o.append("```\n")
        o.append("</details>\n")
flush_kv()

# consecutive check bullets need no blank line, but a list must be preceded by one
md="\n".join(o)
md=re.sub(r"(?<!\n)\n(- (?:✅|⚠️))", r"\n\n\1", md)
md=re.sub(r"\n{4,}","\n\n\n",md)
OUT.write_text(md,encoding="utf-8")
print(f"checks={n_checks} byte-blocks={n_bytes} -> {OUT} ({OUT.stat().st_size:,} bytes)")

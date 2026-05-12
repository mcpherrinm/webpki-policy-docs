#!/usr/bin/env python3
"""
Build a single self-contained index.html that combines all source policy documents
and all extracted requirements into a navigable reference site.

Features:
  - 7 source documents (CABF BR, Mozilla, Chrome, Apple, Microsoft, CCADB, LE CP/CPS),
    rendered in-browser from embedded markdown with marked.js.
  - 4 derived-requirement documents (Roots, Cross-Certs, Intermediates, Leaves),
    each parsed into individual numbered requirements with clickable citation chips.
  - Click a citation in a requirement → scroll to that section in the source doc.
  - Each source section heading shows a "Cited by N" badge linking back to derived requirements.
  - Per-requirement notes persisted in browser localStorage.
  - Import/Export notes as JSON.

Output: writes index.html to the project root.
"""

import html
import json
import os
import re
import sys
import urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))

SRC_DOCS = [
    ("cabf_br", "CABF BR", "cabf_br.md"),
    ("mozilla", "Mozilla", "mozilla.md"),
    ("chrome", "Chrome", "chrome.md"),
    ("apple", "Apple", "apple.md"),
    ("microsoft", "Microsoft", "microsoft.md"),
    ("ccadb", "CCADB", "ccadb.md"),
    ("letsencrypt_cp_cps", "LE CP/CPS", "letsencrypt_cp_cps.md"),
]

REQ_DOCS = [
    ("roots", "Roots", "roots.md"),
    ("cross-certs", "Cross-Certs", "cross-certs.md"),
    ("intermediates", "Intermediates", "intermediates.md"),
    ("leaves", "Leaves", "leaves.md"),
]

# Map citation prefix (as it appears in requirement markdown) to source doc key.
CITATION_SRC_TO_KEY = {
    "CABF BR": "cabf_br",
    "Mozilla": "mozilla",
    "Chrome": "chrome",
    "Apple": "apple",
    "Microsoft": "microsoft",
    "CCADB": "ccadb",
    "LE": "letsencrypt_cp_cps",
}


def parse_citations(text):
    """Extract policy citations from a requirement's body text.

    Citations look like [CABF BR §7.1.2.10.2] or [Mozilla §5.1.1, §5.1.2; CABF BR §6.1.5].
    Returns list of {src, doc, sec, parenthetical}.
    """
    cits = []
    for m in re.finditer(r"\[([^\]]+)\]", text):
        inner = m.group(1)
        # Multiple citations in one bracket are separated by ';'
        for seg in inner.split(";"):
            seg = seg.strip()
            for src, key in CITATION_SRC_TO_KEY.items():
                if seg.startswith(src + " ") or seg == src or seg.startswith(src + " §"):
                    rest = seg[len(src):].strip()
                    # Capture optional parenthetical hint (e.g. "(Root CA profile)")
                    pm = re.search(r"\(([^)]+)\)", rest)
                    paren = pm.group(1) if pm else ""
                    # Section numbers look like §X[.Y[.Z]] — capture all of them
                    secs = re.findall(r"§([0-9]+(?:\.[0-9]+)*)", rest)
                    if secs:
                        for s in secs:
                            cits.append({"src": src, "doc": key, "sec": s, "paren": paren})
                    else:
                        cits.append({"src": src, "doc": key, "sec": "", "paren": paren})
                    break
    return cits


def slugify(s, maxlen=40):
    s = re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")
    return s[:maxlen]


def parse_requirement_doc(path):
    """Parse a requirement markdown file into structured items.

    Returns list of {section_path, section_anchor, item, text, citations, id}.
    """
    text = open(path).read()
    out = []
    section_stack = []   # current heading path
    section_anchors = [] # parallel: anchor for each stack level
    in_code = False
    last_section_anchor = "top"

    for line in text.splitlines():
        if line.startswith("```"):
            in_code = not in_code
            continue
        if in_code:
            continue
        m = re.match(r"^(#{1,6})\s+(.+?)$", line)
        if m:
            depth = len(m.group(1))
            label = m.group(2).strip()
            section_stack = section_stack[: depth - 1] + [label]
            # Anchor: prefer leading section number like "1.6.3" → "1-6-3"
            num = re.match(r"^(\d+(?:\.\d+)*)\s", label)
            if num:
                anchor = num.group(1).replace(".", "-")
            else:
                anchor = slugify(label)
            section_anchors = section_anchors[: depth - 1] + [anchor]
            last_section_anchor = "-".join(section_anchors)
            continue
        m = re.match(r"^(\d+)\.\s+(.+?)$", line)
        if m:
            n = int(m.group(1))
            body = m.group(2).strip()
            citations = parse_citations(body)
            section_path = " > ".join(section_stack)
            out.append({
                "section_path": section_path,
                "section_anchor": last_section_anchor,
                "item": n,
                "text": body,
                "citations": citations,
            })
    # Assign unique IDs that include the section to disambiguate (two sections may both
    # have "item 1" — section_anchor + item makes the ID unique).
    for it in out:
        # Document-scoped item id: <section_anchor>.<item>
        it["item_id"] = f"{it['section_anchor']}.{it['item']}"
    # Document key is set by caller.
    return out


def build_reverse_index(req_docs):
    """Build map: 'doc_key#sec-X-Y-Z' → list of '<req_doc_key>::<item_id>' that cite that source section."""
    reverse = {}
    for req_doc_key, doc in req_docs.items():
        for it in doc["items"]:
            for c in it["citations"]:
                if c["sec"]:
                    anchor = "sec-" + c["sec"].replace(".", "-")
                    key = f"{c['doc']}#{anchor}"
                    target = f"{req_doc_key}::{it['item_id']}"
                    reverse.setdefault(key, []).append(target)
                else:
                    # citation with no section number — link to top of doc
                    key = f"{c['doc']}#top"
                    target = f"{req_doc_key}::{it['item_id']}"
                    reverse.setdefault(key, []).append(target)
    return reverse


def load_marked_js():
    """Return the marked.min.js source, downloading if needed."""
    local = os.path.join(ROOT, "build", "marked.min.js")
    os.makedirs(os.path.dirname(local), exist_ok=True)
    if not os.path.exists(local):
        url = "https://cdn.jsdelivr.net/npm/marked@12.0.0/marked.min.js"
        sys.stderr.write(f"Downloading marked.js from {url}...\n")
        with urllib.request.urlopen(url, timeout=30) as resp:
            data = resp.read()
        with open(local, "wb") as f:
            f.write(data)
    return open(local, "rb").read().decode("utf-8")


def build_html():
    # Source docs: raw markdown for browser-side rendering
    src_data = {}
    for key, label, path in SRC_DOCS:
        with open(os.path.join(ROOT, path), "r", encoding="utf-8") as f:
            src_data[key] = {"label": label, "filename": path, "raw": f.read()}

    # Requirement docs: parsed structured items
    req_data = {}
    for key, label, path in REQ_DOCS:
        items = parse_requirement_doc(os.path.join(ROOT, path))
        with open(os.path.join(ROOT, path), "r", encoding="utf-8") as f:
            raw = f.read()
        req_data[key] = {
            "label": label,
            "filename": path,
            "raw": raw,
            "items": items,
        }

    reverse_index = build_reverse_index(req_data)

    marked_js = load_marked_js()

    # Build the page
    src_data_json = json.dumps(src_data, ensure_ascii=False)
    req_data_json = json.dumps(req_data, ensure_ascii=False)
    reverse_json = json.dumps(reverse_index, ensure_ascii=False)

    src_nav = "".join(
        f'<button class="navbtn src" data-kind="src" data-doc="{html.escape(k)}">{html.escape(lbl)}</button>'
        for k, lbl, _ in SRC_DOCS
    )
    req_nav = "".join(
        f'<button class="navbtn req" data-kind="req" data-doc="{html.escape(k)}">{html.escape(lbl)}</button>'
        for k, lbl, _ in REQ_DOCS
    )

    html_template = HTML_TEMPLATE.format(
        marked_js=marked_js,
        src_data_json=src_data_json,
        req_data_json=req_data_json,
        reverse_json=reverse_json,
        src_nav=src_nav,
        req_nav=req_nav,
    )
    out_path = os.path.join(ROOT, "index.html")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html_template)
    sys.stderr.write(f"Wrote {out_path} ({os.path.getsize(out_path)} bytes)\n")


HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>WebPKI Policy Reference</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root {{
    --bg: #fdfdfb;
    --bg-alt: #f3f1ec;
    --fg: #1c1c1c;
    --muted: #6a6a6a;
    --accent: #2c5d8f;
    --accent-bg: #e8f0f8;
    --link: #1e4d80;
    --link-hover: #102a4a;
    --border: #d9d6cf;
    --warn: #b88600;
    --warn-bg: #fff3d6;
    --code-bg: #efece4;
    --note-bg: #fffceb;
    --note-border: #e1dbb6;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: var(--bg);
    color: var(--fg);
    line-height: 1.5;
  }}
  header {{
    background: var(--bg-alt);
    border-bottom: 1px solid var(--border);
    padding: 12px 20px;
    position: sticky;
    top: 0;
    z-index: 10;
  }}
  header h1 {{
    margin: 0 0 8px 0;
    font-size: 16px;
    font-weight: 600;
  }}
  .nav-row {{
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
    margin-bottom: 6px;
  }}
  .nav-label {{
    color: var(--muted);
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    margin-right: 6px;
  }}
  .navbtn {{
    border: 1px solid var(--border);
    background: white;
    color: var(--fg);
    padding: 4px 10px;
    border-radius: 4px;
    font-size: 13px;
    cursor: pointer;
    font-family: inherit;
  }}
  .navbtn:hover {{ background: var(--accent-bg); }}
  .navbtn.active {{
    background: var(--accent);
    color: white;
    border-color: var(--accent);
  }}
  .navbtn.src {{ font-style: italic; }}
  .navbtn.req {{ font-weight: 600; }}
  .controls {{ margin-left: auto; display: flex; gap: 6px; }}
  .controls button, .controls label {{
    background: white;
    border: 1px solid var(--border);
    padding: 4px 10px;
    border-radius: 4px;
    font-size: 12px;
    cursor: pointer;
    font-family: inherit;
  }}
  .controls button:hover, .controls label:hover {{ background: var(--accent-bg); }}
  #search {{
    border: 1px solid var(--border);
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 13px;
    width: 200px;
  }}
  main {{
    padding: 20px 24px 80px;
    max-width: 1100px;
    margin: 0 auto;
  }}
  /* Requirement view */
  .req-page h1 {{ font-size: 22px; margin-top: 8px; }}
  .req-page .doc-intro {{
    color: var(--muted);
    font-size: 13px;
    margin-bottom: 16px;
  }}
  .req-page h2.section {{
    font-size: 14px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--muted);
    margin-top: 28px;
    margin-bottom: 8px;
    padding-bottom: 4px;
    border-bottom: 1px solid var(--border);
  }}
  .req-card {{
    background: white;
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 12px 14px;
    margin-bottom: 10px;
  }}
  .req-card.active {{
    border-color: var(--accent);
    box-shadow: 0 0 0 2px var(--accent-bg);
  }}
  .req-card .num {{
    color: var(--muted);
    font-size: 12px;
    font-weight: 600;
  }}
  .req-card .text {{
    margin: 4px 0 6px 0;
    font-size: 14px;
  }}
  .req-card .text code {{
    background: var(--code-bg);
    padding: 1px 4px;
    border-radius: 3px;
    font-size: 12.5px;
  }}
  .citations {{
    display: flex;
    flex-wrap: wrap;
    gap: 4px 6px;
    margin-bottom: 8px;
  }}
  .cite-chip {{
    display: inline-block;
    background: var(--accent-bg);
    color: var(--link);
    font-size: 11px;
    padding: 1px 7px;
    border-radius: 11px;
    text-decoration: none;
    border: 1px solid transparent;
    cursor: pointer;
  }}
  .cite-chip:hover {{
    background: var(--accent);
    color: white;
  }}
  .cite-chip .src-name {{ font-weight: 600; }}
  .note-toggle {{
    background: none;
    border: none;
    color: var(--muted);
    font-size: 11px;
    cursor: pointer;
    padding: 0;
    margin: 0;
  }}
  .note-toggle:hover {{ color: var(--accent); }}
  .note-toggle.has-note {{ color: var(--warn); font-weight: 600; }}
  .note-area {{
    margin-top: 6px;
    background: var(--note-bg);
    border: 1px solid var(--note-border);
    border-radius: 4px;
    padding: 6px 8px;
  }}
  .note-area textarea {{
    width: 100%;
    min-height: 50px;
    border: none;
    background: transparent;
    font: inherit;
    font-size: 13px;
    resize: vertical;
    outline: none;
  }}
  .note-area .meta {{
    font-size: 10px;
    color: var(--muted);
    margin-top: 4px;
    display: flex;
    justify-content: space-between;
  }}
  /* Source view */
  .src-page h1 {{ font-size: 22px; margin-top: 8px; }}
  .src-page .doc-intro {{
    color: var(--muted);
    font-size: 13px;
    margin-bottom: 16px;
  }}
  .src-toc {{
    background: var(--bg-alt);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 10px 12px;
    margin-bottom: 20px;
    font-size: 12.5px;
    columns: 2;
    column-gap: 18px;
  }}
  .src-toc summary {{ cursor: pointer; font-weight: 600; column-span: all; }}
  .src-toc a {{
    display: block;
    text-decoration: none;
    color: var(--link);
    padding: 1px 0;
    break-inside: avoid;
  }}
  .src-toc a:hover {{ color: var(--accent); text-decoration: underline; }}
  .src-toc a[data-lvl="1"] {{ font-weight: 600; }}
  .src-toc a[data-lvl="2"] {{ padding-left: 8px; }}
  .src-toc a[data-lvl="3"] {{ padding-left: 16px; }}
  .src-toc a[data-lvl="4"] {{ padding-left: 24px; font-size: 12px; }}
  .src-toc a[data-lvl="5"] {{ padding-left: 32px; font-size: 11.5px; color: var(--muted); }}
  .src-content h1, .src-content h2, .src-content h3, .src-content h4, .src-content h5, .src-content h6 {{
    position: relative;
    scroll-margin-top: 90px;
  }}
  .src-content h1 {{ font-size: 20px; border-bottom: 2px solid var(--border); padding-bottom: 4px; }}
  .src-content h2 {{ font-size: 17px; }}
  .src-content h3 {{ font-size: 15px; }}
  .src-content h4 {{ font-size: 14px; }}
  .src-content h5 {{ font-size: 13.5px; }}
  .src-content h6 {{ font-size: 13px; color: var(--muted); }}
  .src-content pre {{
    background: var(--code-bg);
    border-radius: 4px;
    padding: 8px 10px;
    overflow-x: auto;
    font-size: 12px;
  }}
  .src-content code {{
    background: var(--code-bg);
    padding: 1px 4px;
    border-radius: 3px;
    font-size: 12.5px;
  }}
  .src-content pre code {{ background: none; padding: 0; }}
  .src-content table {{
    border-collapse: collapse;
    margin: 10px 0;
    font-size: 12.5px;
    max-width: 100%;
  }}
  .src-content table th, .src-content table td {{
    border: 1px solid var(--border);
    padding: 4px 8px;
    vertical-align: top;
  }}
  .src-content table th {{ background: var(--bg-alt); }}
  .src-content a {{ color: var(--link); }}
  .src-content blockquote {{
    border-left: 3px solid var(--accent);
    background: var(--accent-bg);
    margin: 8px 0;
    padding: 6px 12px;
    color: var(--fg);
  }}
  .cited-by-badge {{
    display: inline-block;
    margin-left: 8px;
    font-size: 11px;
    font-weight: normal;
    color: var(--warn);
    background: var(--warn-bg);
    padding: 1px 7px;
    border-radius: 10px;
    border: 1px solid var(--note-border);
    cursor: pointer;
    user-select: none;
    vertical-align: middle;
  }}
  .cited-by-badge:hover {{ background: var(--warn); color: white; }}
  .cited-by-list {{
    margin: 6px 0 10px 0;
    padding: 8px 10px;
    background: var(--warn-bg);
    border: 1px solid var(--note-border);
    border-radius: 4px;
    font-size: 12.5px;
  }}
  .cited-by-list a {{
    display: inline-block;
    margin: 2px 8px 2px 0;
    color: var(--link);
    text-decoration: none;
    border-bottom: 1px dotted var(--link);
  }}
  .cited-by-list a:hover {{ color: var(--accent); }}
  .src-section {{ scroll-margin-top: 90px; }}
  .src-section.flash {{ animation: flash 1.6s ease-out; }}
  .req-card.flash {{ animation: flash 1.6s ease-out; }}
  @keyframes flash {{
    0% {{ background: var(--warn-bg); }}
    100% {{ background: white; }}
  }}
  .empty-state {{ color: var(--muted); font-style: italic; padding: 40px 0; text-align: center; }}
  #search-results {{
    background: white;
    border: 1px solid var(--border);
    border-radius: 4px;
    margin-bottom: 16px;
    padding: 8px 12px;
    font-size: 12px;
  }}
  .search-hit {{
    padding: 4px 0;
    border-bottom: 1px solid var(--border);
  }}
  .search-hit:last-child {{ border: none; }}
  .search-hit a {{ color: var(--link); text-decoration: none; font-weight: 600; }}
  .search-hit .ctx {{ color: var(--muted); }}
  mark {{ background: #ffe88a; padding: 0 1px; }}
</style>
</head>
<body>

<header>
  <h1>WebPKI Policy Reference</h1>
  <div class="nav-row">
    <span class="nav-label">Requirements:</span>
    {req_nav}
    <span class="nav-label" style="margin-left:8px;">Sources:</span>
    {src_nav}
    <div class="controls">
      <input id="search" type="search" placeholder="Search (Enter to run)…">
      <button id="exportBtn" title="Download all notes as JSON">Export notes</button>
      <label>
        Import notes
        <input id="importInput" type="file" accept="application/json" style="display:none">
      </label>
    </div>
  </div>
</header>

<main id="content"></main>

<script>
{marked_js}
</script>

<script>
"use strict";

// === Embedded data ===
const SRC_DATA = {src_data_json};
const REQ_DATA = {req_data_json};
const REVERSE  = {reverse_json};
const SRC_LABELS = {{
{src_label_map}
}};
const REQ_LABELS = {{
{req_label_map}
}};

// === marked.js configuration ===
marked.setOptions({{ gfm: true, breaks: false }});

// === Notes (localStorage) ===
const NOTE_KEY_PREFIX = "webpki-policy-notes::v1::";

function noteKey(reqDocKey, itemId) {{
  return NOTE_KEY_PREFIX + reqDocKey + "::" + itemId;
}}

function getNote(reqDocKey, itemId) {{
  try {{ return localStorage.getItem(noteKey(reqDocKey, itemId)) || ""; }}
  catch (e) {{ return ""; }}
}}

function setNote(reqDocKey, itemId, text) {{
  try {{
    if (text.trim() === "") {{
      localStorage.removeItem(noteKey(reqDocKey, itemId));
    }} else {{
      localStorage.setItem(noteKey(reqDocKey, itemId), text);
    }}
  }} catch (e) {{ console.error(e); }}
}}

function allNotes() {{
  const out = {{}};
  for (let i = 0; i < localStorage.length; i++) {{
    const k = localStorage.key(i);
    if (k && k.startsWith(NOTE_KEY_PREFIX)) {{
      const rest = k.substring(NOTE_KEY_PREFIX.length);
      out[rest] = localStorage.getItem(k);
    }}
  }}
  return out;
}}

function importNotesObject(obj, mode) {{
  // mode: 'merge' adds notes, 'replace' clears existing first
  if (mode === "replace") {{
    const keys = [];
    for (let i = 0; i < localStorage.length; i++) {{
      const k = localStorage.key(i);
      if (k && k.startsWith(NOTE_KEY_PREFIX)) keys.push(k);
    }}
    keys.forEach((k) => localStorage.removeItem(k));
  }}
  let count = 0;
  for (const composite of Object.keys(obj)) {{
    const v = obj[composite];
    if (typeof v !== "string") continue;
    if (v.trim() === "") continue;
    localStorage.setItem(NOTE_KEY_PREFIX + composite, v);
    count++;
  }}
  return count;
}}

// === Rendering helpers ===

function escapeHtml(s) {{
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}}

function inlineMarkdownToHtml(s) {{
  // Render inline markdown (no block elements). marked.parseInline()
  return marked.parseInline(s);
}}

function citeAnchor(cite) {{
  if (cite.sec) {{
    return "src/" + cite.doc + "/sec-" + cite.sec.replace(/\./g, "-");
  }}
  return "src/" + cite.doc + "/top";
}}

function renderCitations(cits) {{
  if (!cits || cits.length === 0) return "";
  return '<div class="citations">' + cits.map((c) => {{
    const paren = c.paren ? ' <span style="opacity:0.7;font-size:10px;">(' + escapeHtml(c.paren) + ')</span>' : "";
    return '<a class="cite-chip" href="#' + citeAnchor(c) + '">' +
           '<span class="src-name">' + escapeHtml(c.src) + '</span>' + (c.sec ? ' §' + escapeHtml(c.sec) : "") + paren +
           '</a>';
  }}).join("") + '</div>';
}}

function reqAnchor(reqDocKey, item) {{
  return "req/" + reqDocKey + "/" + item.item_id;
}}

// === Page renderers ===

function renderRequirementPage(key) {{
  const doc = REQ_DATA[key];
  const container = document.createElement("div");
  container.className = "req-page";
  container.innerHTML = '<h1>' + escapeHtml(doc.label) + ' — Requirements</h1>' +
    '<div class="doc-intro">' + escapeHtml(doc.items.length + " numbered requirements parsed from " + doc.filename + ".") + '</div>';

  let lastSection = null;
  for (const it of doc.items) {{
    if (it.section_path !== lastSection) {{
      const h = document.createElement("h2");
      h.className = "section";
      h.textContent = it.section_path;
      container.appendChild(h);
      lastSection = it.section_path;
    }}
    const card = document.createElement("div");
    card.className = "req-card";
    card.id = reqAnchor(key, it);
    const note = getNote(key, it.item_id);
    card.innerHTML =
      '<div class="num">#' + it.item_id + '</div>' +
      '<div class="text">' + inlineMarkdownToHtml(it.text) + '</div>' +
      renderCitations(it.citations) +
      '<button class="note-toggle ' + (note ? "has-note" : "") + '" data-req="' + escapeHtml(it.item_id) + '">' +
        (note ? "📝 Note (saved)" : "+ Add note") +
      '</button>' +
      '<div class="note-area" style="display:' + (note ? "block" : "none") + '" data-area="' + escapeHtml(it.item_id) + '">' +
        '<textarea data-note="' + escapeHtml(it.item_id) + '" placeholder="Notes for this requirement…">' + escapeHtml(note) + '</textarea>' +
        '<div class="meta"><span class="save-status"></span><span style="font-family:monospace">' + escapeHtml(key + "::" + it.item_id) + '</span></div>' +
      '</div>';
    container.appendChild(card);
  }}
  return container;
}}

function renderSourcePage(key) {{
  const doc = SRC_DATA[key];
  const container = document.createElement("div");
  container.className = "src-page";
  const intro = '<h1>' + escapeHtml(doc.label) + '</h1>' +
    '<div class="doc-intro">Rendered from ' + escapeHtml(doc.filename) +
    '. Each section heading shows a "Cited by N" badge when extracted requirements reference it.</div>';
  container.innerHTML = intro;

  const tocBox = document.createElement("details");
  tocBox.className = "src-toc";
  tocBox.innerHTML = '<summary>Table of contents</summary><div id="toc-' + escapeHtml(key) + '"></div>';
  container.appendChild(tocBox);

  const body = document.createElement("div");
  body.className = "src-content";
  body.innerHTML = marked.parse(doc.raw);
  container.appendChild(body);

  // Post-process: add anchors, "cited-by" badges, build TOC.
  const toc = tocBox.querySelector("#toc-" + key);
  body.querySelectorAll("h1, h2, h3, h4, h5, h6").forEach((h) => {{
    const text = h.textContent.trim();
    const numMatch = text.match(/^(\d+(?:\.\d+)*)/);
    let anchor;
    if (numMatch) {{
      anchor = "sec-" + numMatch[1].replace(/\./g, "-");
    }} else {{
      anchor = "sec-" + text.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").substring(0, 40);
    }}
    h.id = anchor;
    h.classList.add("src-section");
    // Add "cited by" badge
    const fullKey = key + "#" + anchor;
    const citingReqs = REVERSE[fullKey];
    if (citingReqs && citingReqs.length > 0) {{
      const badge = document.createElement("span");
      badge.className = "cited-by-badge";
      badge.textContent = "Cited by " + citingReqs.length;
      badge.dataset.fullkey = fullKey;
      h.appendChild(badge);
    }}
    // TOC entry
    const link = document.createElement("a");
    link.href = "#src/" + key + "/" + anchor;
    link.textContent = text.replace(/Cited by \d+/, "").trim();
    link.dataset.lvl = h.tagName.substring(1);
    toc.appendChild(link);
  }});

  return container;
}}

// === Routing / navigation ===

function activate(kind, doc) {{
  document.querySelectorAll(".navbtn").forEach((b) => b.classList.remove("active"));
  const btn = document.querySelector('.navbtn[data-kind="' + kind + '"][data-doc="' + doc + '"]');
  if (btn) btn.classList.add("active");
  const main = document.getElementById("content");
  main.innerHTML = "";
  if (kind === "req") {{
    main.appendChild(renderRequirementPage(doc));
  }} else {{
    main.appendChild(renderSourcePage(doc));
  }}
}}

function navigateHash() {{
  const hash = window.location.hash.replace(/^#/, "");
  if (!hash) {{
    activate("req", "roots");
    return;
  }}
  const parts = hash.split("/");
  // forms:
  //   req/<key>                    → show requirement doc
  //   req/<key>/<item_id>           → show requirement doc, scroll to item
  //   src/<key>                    → show source doc
  //   src/<key>/<anchor>            → show source doc, scroll to anchor
  if (parts[0] === "req") {{
    activate("req", parts[1]);
    if (parts[2]) {{
      const itemId = parts.slice(2).join("/");
      setTimeout(() => {{
        const el = document.getElementById("req/" + parts[1] + "/" + itemId);
        if (el) {{
          el.scrollIntoView({{ behavior: "smooth", block: "center" }});
          el.classList.add("flash");
        }}
      }}, 30);
    }}
  }} else if (parts[0] === "src") {{
    activate("src", parts[1]);
    if (parts[2]) {{
      setTimeout(() => {{
        const el = document.getElementById(parts[2]);
        if (el) {{
          el.scrollIntoView({{ behavior: "smooth", block: "start" }});
          el.classList.add("flash");
        }}
      }}, 30);
    }}
  }} else {{
    activate("req", "roots");
  }}
}}

window.addEventListener("hashchange", navigateHash);

// === Event delegation ===

document.addEventListener("click", (e) => {{
  // Nav button
  const navbtn = e.target.closest(".navbtn");
  if (navbtn) {{
    const kind = navbtn.dataset.kind;
    const doc = navbtn.dataset.doc;
    window.location.hash = "#" + kind + "/" + doc;
    return;
  }}
  // Note toggle button
  const toggle = e.target.closest(".note-toggle");
  if (toggle) {{
    const reqId = toggle.dataset.req;
    const area = document.querySelector('.note-area[data-area="' + reqId + '"]');
    if (area) {{
      const shown = area.style.display !== "none";
      area.style.display = shown ? "none" : "block";
      if (!shown) area.querySelector("textarea").focus();
    }}
    return;
  }}
  // "Cited by" badge
  const badge = e.target.closest(".cited-by-badge");
  if (badge) {{
    const fullKey = badge.dataset.fullkey;
    const reqs = REVERSE[fullKey] || [];
    // Check if a list is already open after this heading
    const heading = badge.parentElement;
    const next = heading.nextElementSibling;
    if (next && next.classList && next.classList.contains("cited-by-list")) {{
      next.remove();
      return;
    }}
    const list = document.createElement("div");
    list.className = "cited-by-list";
    list.innerHTML = '<strong>Cited by:</strong> ' + reqs.map((r) => {{
      const [reqDocKey, itemId] = r.split("::");
      const label = REQ_LABELS[reqDocKey] || reqDocKey;
      return '<a href="#req/' + reqDocKey + '/' + itemId + '" data-target="' + r + '">' + label + ' ' + itemId + '</a>';
    }}).join("");
    heading.parentNode.insertBefore(list, heading.nextSibling);
    return;
  }}
}});

document.addEventListener("input", (e) => {{
  if (e.target.matches("textarea[data-note]")) {{
    const reqId = e.target.dataset.note;
    const text = e.target.value;
    const docKey = currentReqDocKey();
    if (!docKey) return;
    setNote(docKey, reqId, text);
    const meta = e.target.parentElement.querySelector(".save-status");
    if (meta) {{
      meta.textContent = "saved " + new Date().toLocaleTimeString();
      setTimeout(() => {{ if (meta.textContent.startsWith("saved")) meta.textContent = ""; }}, 2500);
    }}
    // Update toggle label
    const card = e.target.closest(".req-card");
    if (card) {{
      const toggle = card.querySelector(".note-toggle");
      if (toggle) {{
        if (text.trim()) {{
          toggle.classList.add("has-note");
          toggle.textContent = "📝 Note (saved)";
        }} else {{
          toggle.classList.remove("has-note");
          toggle.textContent = "+ Add note";
        }}
      }}
    }}
  }}
}});

function currentReqDocKey() {{
  const active = document.querySelector('.navbtn.active[data-kind="req"]');
  return active ? active.dataset.doc : null;
}}

// === Export / Import ===

document.getElementById("exportBtn").addEventListener("click", () => {{
  const data = allNotes();
  const blob = new Blob([JSON.stringify(data, null, 2)], {{ type: "application/json" }});
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "webpki-policy-notes-" + new Date().toISOString().substring(0, 10) + ".json";
  a.click();
  URL.revokeObjectURL(url);
}});

document.getElementById("importInput").addEventListener("change", (e) => {{
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (ev) => {{
    try {{
      const obj = JSON.parse(ev.target.result);
      const mode = confirm("OK = MERGE imported notes with existing.\\nCancel = REPLACE all existing notes.")
        ? "merge" : "replace";
      const n = importNotesObject(obj, mode);
      alert("Imported " + n + " notes (" + mode + ").");
      navigateHash(); // re-render current page
    }} catch (err) {{
      alert("Import failed: " + err.message);
    }}
    e.target.value = "";
  }};
  reader.readAsText(file);
}});

// === Search ===
document.getElementById("search").addEventListener("keydown", (e) => {{
  if (e.key === "Enter") {{
    const q = e.target.value.trim();
    if (!q) return;
    runSearch(q);
  }}
}});

function runSearch(q) {{
  const qLower = q.toLowerCase();
  const hits = [];
  for (const docKey of Object.keys(REQ_DATA)) {{
    for (const it of REQ_DATA[docKey].items) {{
      if (it.text.toLowerCase().includes(qLower)) {{
        hits.push({{ docKey, item: it }});
      }}
    }}
  }}
  const main = document.getElementById("content");
  main.innerHTML = "";
  const c = document.createElement("div");
  c.innerHTML = '<h1>Search: ' + escapeHtml(q) + '</h1>' +
    '<div class="doc-intro">' + hits.length + ' requirement(s) matched.</div>';
  document.querySelectorAll(".navbtn").forEach((b) => b.classList.remove("active"));
  const list = document.createElement("div");
  list.id = "search-results";
  hits.forEach(({{ docKey, item }}) => {{
    const re = new RegExp("(" + q.replace(/[.*+?^${{}}()|[\]\\\\]/g, "\\\\$&") + ")", "ig");
    const snippet = item.text.replace(re, "<mark>$1</mark>");
    const div = document.createElement("div");
    div.className = "search-hit";
    div.innerHTML = '<a href="#req/' + docKey + '/' + item.item_id + '">' +
      escapeHtml(REQ_LABELS[docKey]) + ' ' + escapeHtml(item.item_id) + '</a> ' +
      '<span class="ctx">' + escapeHtml(item.section_path) + '</span>' +
      '<div>' + snippet + '</div>';
    list.appendChild(div);
  }});
  c.appendChild(list);
  main.appendChild(c);
}}

// === Init ===
navigateHash();
</script>

</body>
</html>
"""


def main():
    # Build the label maps that get embedded as JS objects (we need them for the template).
    src_label_map = ",\n".join(f'  "{k}": "{lbl}"' for k, lbl, _ in SRC_DOCS)
    req_label_map = ",\n".join(f'  "{k}": "{lbl}"' for k, lbl, _ in REQ_DOCS)
    # Read & build everything (HTML_TEMPLATE uses .format(); we need to also supply label maps)
    src_data = {}
    for key, label, path in SRC_DOCS:
        with open(os.path.join(ROOT, path), "r", encoding="utf-8") as f:
            src_data[key] = {"label": label, "filename": path, "raw": f.read()}

    req_data = {}
    for key, label, path in REQ_DOCS:
        items = parse_requirement_doc(os.path.join(ROOT, path))
        with open(os.path.join(ROOT, path), "r", encoding="utf-8") as f:
            raw = f.read()
        req_data[key] = {"label": label, "filename": path, "raw": raw, "items": items}

    reverse_index = build_reverse_index(req_data)
    marked_js = load_marked_js()

    src_data_json = json.dumps(src_data, ensure_ascii=False)
    req_data_json = json.dumps(req_data, ensure_ascii=False)
    reverse_json = json.dumps(reverse_index, ensure_ascii=False)

    src_nav = "".join(
        f'<button class="navbtn src" data-kind="src" data-doc="{html.escape(k)}">{html.escape(lbl)}</button>'
        for k, lbl, _ in SRC_DOCS
    )
    req_nav = "".join(
        f'<button class="navbtn req" data-kind="req" data-doc="{html.escape(k)}">{html.escape(lbl)}</button>'
        for k, lbl, _ in REQ_DOCS
    )

    rendered = HTML_TEMPLATE.format(
        marked_js=marked_js,
        src_data_json=src_data_json,
        req_data_json=req_data_json,
        reverse_json=reverse_json,
        src_nav=src_nav,
        req_nav=req_nav,
        src_label_map=src_label_map,
        req_label_map=req_label_map,
    )
    out_path = os.path.join(ROOT, "index.html")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(rendered)
    print(f"Wrote {out_path} ({os.path.getsize(out_path):,} bytes)")


if __name__ == "__main__":
    main()

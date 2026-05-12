#!/usr/bin/env python3
"""Build a single self-contained index.html for browsing WebPKI policy docs
with per-element commentary (sections, paragraphs, list items, table rows).

Outputs:
  - index.html       single-file webapp (markdown rendered by marked.js)
  - id-manifest.json reference of every commentable element ID (for external
                    tooling — e.g. `// webpki:cabf_br#7.1.2.10.2/p3` in code)

Stable element-ID scheme (computed by both Python and the in-page JS walker):
  - Section ID = numeric prefix of the heading ("7.1.2.10.2"), else a slug.
                 Headings under the same parent that collide get "-2", "-3".
  - Within a section, sequential counters per kind:
      paragraphs   p1, p2, ...
      list items   li1, li2, ...   (flat across nested lists and ordered/unordered)
      table rows   tr1, tr2, ...   (body rows only, header row skipped)
  - A fully-qualified ref is "<doc_key>#<section_id>[/<kind><n>]".
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


# ---------------------------------------------------------------------------
# Markdown structural parser (enumeration only — we do not render to HTML
# here; the browser does that with marked.js using the same element-order
# rules, so the IDs computed here match the IDs the page assigns).
# ---------------------------------------------------------------------------

_HEADING_NUM_RE = re.compile(r"^(\d+(?:\.\d+)*)\.?(?:\s|$)")
_LIST_ITEM_RE = re.compile(r"^\s*(?:[-*+]|\d+\.)\s+")
_TABLE_SEP_RE = re.compile(r"^\s*\|?\s*:?-+:?(\s*\|\s*:?-+:?)+\s*\|?\s*$")


def slugify(s, maxlen=48):
    s = re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")
    return s[:maxlen] or "section"


def section_id_from_heading(text):
    """Return (id, title) for a heading.

    "7.1.2.10.2 Subject Information"  → ("7.1.2.10.2", "Subject Information")
    "4.1.5.1. All Audit Letter…"     → ("4.1.5.1",    "All Audit Letter…")
    "Introduction"                    → ("introduction", "Introduction")
    """
    text = text.strip()
    m = _HEADING_NUM_RE.match(text)
    if m:
        num = m.group(1)
        rest = text[m.end():].strip().lstrip(".").strip()
        return num, rest or num
    return slugify(text), text


def parse_doc(md_text):
    """Parse a markdown document into sections + elements.

    Returns:
      {
        "title":    <first H1 text> or None,
        "sections": [
          { "id", "level", "title", "raw_heading", "anchor",
            "elements": [ {"kind": "p"|"li"|"tr", "ord", "id", "snippet"}, ... ],
          }
        ],
        "preamble_elements": [ ... ]  # elements seen before the first heading
      }
    """
    title = None
    sections = []
    preamble_elements = []
    seen_section_ids = {}

    cur_section = None
    counters = {"p": 0, "li": 0, "tr": 0}

    def cur_target_elements():
        return cur_section["elements"] if cur_section is not None else preamble_elements

    def cur_id_prefix():
        return cur_section["id"] if cur_section is not None else "_preamble"

    # Counting rule (must match the JS walker that runs on marked.js output):
    #   p  counts only top-level paragraphs in a section — paragraphs nested
    #      inside <li>, <blockquote>, <td>, <th> are NOT separately counted.
    #   li counts every <li>, nested or not, flat across all lists in section.
    #   tr counts data rows (i.e., rows inside <tbody>, skipping the header).
    in_code = False
    in_para = False
    in_table = False
    in_list = False        # within an open list (possibly multi-paragraph items)
    in_blockquote = False
    last_para_idx = None

    lines = md_text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.lstrip()
        leading = len(line) - len(stripped)

        # Code fence
        if stripped.startswith("```") or stripped.startswith("~~~"):
            in_code = not in_code
            in_para = False
            in_table = False
            in_list = False
            in_blockquote = False
            last_para_idx = None
            i += 1
            continue
        if in_code:
            i += 1
            continue

        # Heading (always closes any open block)
        m = re.match(r"^(#{1,6})\s+(.+?)\s*$", line)
        if m:
            level = len(m.group(1))
            head_text = m.group(2).strip()
            if title is None and level == 1:
                title = head_text
            sid, sec_title = section_id_from_heading(head_text)
            n = seen_section_ids.get(sid, 0) + 1
            seen_section_ids[sid] = n
            if n > 1:
                sid = f"{sid}-{n}"
            cur_section = {
                "id": sid,
                "level": level,
                "title": sec_title,
                "raw_heading": head_text,
                "anchor": "sec-" + sid.replace(".", "-").replace("/", "_"),
                "elements": [],
            }
            sections.append(cur_section)
            counters = {"p": 0, "li": 0, "tr": 0}
            in_para = False
            in_table = False
            in_list = False
            in_blockquote = False
            last_para_idx = None
            i += 1
            continue

        # YAML frontmatter (skip)
        if i == 0 and line.strip() == "---":
            j = i + 1
            while j < len(lines) and lines[j].strip() != "---":
                j += 1
            i = j + 1
            continue

        # Blank line — closes paragraph + table; list/blockquote can survive across blank lines.
        if line.strip() == "":
            in_para = False
            in_table = False
            last_para_idx = None
            i += 1
            continue

        # Horizontal rule
        if re.match(r"^\s*([-*_])\s*\1\s*\1\s*$", line):
            in_para = False
            in_table = False
            in_list = False
            in_blockquote = False
            i += 1
            continue

        # Blockquote line — every `>`-prefixed line is blockquote content. Inside
        # blockquotes we don't count paragraphs (the blockquote isn't a comment target).
        if stripped.startswith(">"):
            in_blockquote = True
            in_para = False
            in_table = False
            i += 1
            continue
        # Any other non-indented line closes blockquote (lazy continuation not modeled).
        if in_blockquote and leading == 0:
            in_blockquote = False

        # List item (any indent)
        if _LIST_ITEM_RE.match(line):
            counters["li"] += 1
            text_after_marker = _LIST_ITEM_RE.sub("", line, count=1).strip()
            cur_target_elements().append({
                "kind": "li",
                "ord": counters["li"],
                "id": cur_id_prefix() + "/li" + str(counters["li"]),
                "snippet": text_after_marker[:200],
            })
            in_list = True
            in_para = False
            in_table = False
            last_para_idx = None
            i += 1
            continue

        # Indented continuation of a list item — do not count as paragraph.
        if in_list and leading >= 2:
            in_para = False
            last_para_idx = None
            i += 1
            continue

        # Non-indented non-list line: list ends.
        if in_list and leading < 2:
            in_list = False

        # Table row — header detection: a `|`-line whose next line is the separator.
        if "|" in line:
            if in_table:
                counters["tr"] += 1
                cur_target_elements().append({
                    "kind": "tr",
                    "ord": counters["tr"],
                    "id": cur_id_prefix() + "/tr" + str(counters["tr"]),
                    "snippet": line.strip()[:200],
                })
                in_para = False
                last_para_idx = None
                i += 1
                continue
            if i + 1 < len(lines) and _TABLE_SEP_RE.match(lines[i + 1]):
                # consume header (not counted) + separator
                in_table = True
                in_para = False
                last_para_idx = None
                i += 2
                continue

        # Separator-only line — open table without header (rare).
        if _TABLE_SEP_RE.match(line):
            in_table = True
            i += 1
            continue

        if in_table:
            in_table = False

        # Paragraph (top-level only — list/blockquote already filtered out).
        if in_blockquote:
            i += 1
            continue
        if not in_para:
            counters["p"] += 1
            cur_target_elements().append({
                "kind": "p",
                "ord": counters["p"],
                "id": cur_id_prefix() + "/p" + str(counters["p"]),
                "snippet": line.strip()[:200],
            })
            in_para = True
            last_para_idx = len(cur_target_elements()) - 1
        else:
            if last_para_idx is not None:
                el = cur_target_elements()[last_para_idx]
                if len(el["snippet"]) < 200:
                    el["snippet"] = (el["snippet"] + " " + line.strip())[:200]
        i += 1

    return {
        "title": title,
        "sections": sections,
        "preamble_elements": preamble_elements,
    }


# ---------------------------------------------------------------------------
# marked.js fetch (same as before)
# ---------------------------------------------------------------------------

def load_marked_js():
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


# ---------------------------------------------------------------------------
# HTML template
# ---------------------------------------------------------------------------

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
    --highlight: #fff09a;
  }}
  * {{ box-sizing: border-box; }}
  html {{ scroll-behavior: smooth; }}
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
    padding: 10px 18px;
    position: sticky;
    top: 0;
    z-index: 20;
  }}
  header h1 {{
    margin: 0 0 6px 0;
    font-size: 15px;
    font-weight: 600;
  }}
  .nav-row {{
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
  }}
  .nav-label {{
    color: var(--muted);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-right: 4px;
  }}
  .navbtn {{
    border: 1px solid var(--border);
    background: white;
    color: var(--fg);
    padding: 3px 10px;
    border-radius: 4px;
    font-size: 12.5px;
    cursor: pointer;
    font-family: inherit;
  }}
  .navbtn:hover {{ background: var(--accent-bg); }}
  .navbtn.active {{
    background: var(--accent);
    color: white;
    border-color: var(--accent);
  }}
  .controls {{
    margin-left: auto;
    display: flex;
    gap: 6px;
    align-items: center;
  }}
  .controls button, .controls input[type="search"] {{
    background: white;
    border: 1px solid var(--border);
    padding: 3px 10px;
    border-radius: 4px;
    font-size: 12px;
    cursor: pointer;
    font-family: inherit;
  }}
  .controls input[type="search"] {{ cursor: text; width: 200px; }}
  .controls button:hover {{ background: var(--accent-bg); }}
  .controls .repo-link {{
    background: white;
    border: 1px solid var(--border);
    padding: 3px 10px;
    border-radius: 4px;
    font-size: 12px;
    font-family: inherit;
    color: var(--fg);
    text-decoration: none;
  }}
  .controls .repo-link:hover {{ background: var(--accent-bg); }}

  /* Loaded-sets bar */
  .loaded-sets-bar {{
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    align-items: center;
    padding: 6px 0 0;
    font-size: 12px;
  }}
  .loaded-sets-bar .label {{
    color: var(--muted);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    margin-right: 4px;
  }}
  .loaded-set-chip {{
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 2px 4px 2px 9px;
    background: white;
    border: 1px solid var(--border);
    border-radius: 11px;
    font-size: 11px;
  }}
  .loaded-set-chip.local {{
    background: var(--bg-alt);
    color: var(--muted);
    font-style: italic;
  }}
  .loaded-set-chip .remove-btn {{
    cursor: pointer;
    color: var(--muted);
    background: none;
    border: none;
    padding: 0 4px;
    font-size: 14px;
    line-height: 1;
    font-family: inherit;
    border-radius: 50%;
  }}
  .loaded-set-chip .remove-btn:hover {{
    color: white;
    background: #c62828;
  }}

  main {{
    padding: 16px 18px 80px;
    max-width: 1600px;
    margin: 0 auto;
  }}

  /* Document title */
  .doc-title {{
    font-size: 22px;
    margin: 4px 0 2px;
  }}
  .doc-meta {{
    color: var(--muted);
    font-size: 12px;
    margin-bottom: 12px;
  }}

  /* Section row: grid with content + N commentary columns */
  .section-row {{
    display: grid;
    grid-template-columns: minmax(0, 1fr) repeat(var(--side-count, 1), var(--side-width, 340px));
    gap: 14px;
    padding: 10px 0;
    border-top: 1px solid var(--border);
  }}
  .section-row.first {{ border-top: none; }}
  .section-row.preamble {{ border-top: none; }}

  /* Main content cell */
  .section-content {{
    min-width: 0;
  }}
  .section-content h1, .section-content h2, .section-content h3,
  .section-content h4, .section-content h5, .section-content h6 {{
    scroll-margin-top: 80px;
    position: relative;
  }}
  .section-content h1 {{ font-size: 19px; border-bottom: 2px solid var(--border); padding-bottom: 3px; }}
  .section-content h2 {{ font-size: 17px; }}
  .section-content h3 {{ font-size: 15px; }}
  .section-content h4 {{ font-size: 14px; }}
  .section-content h5 {{ font-size: 13.5px; }}
  .section-content h6 {{ font-size: 13px; color: var(--muted); }}
  .section-content pre {{
    background: var(--code-bg);
    border-radius: 4px;
    padding: 8px 10px;
    overflow-x: auto;
    font-size: 12px;
  }}
  .section-content code {{
    background: var(--code-bg);
    padding: 1px 4px;
    border-radius: 3px;
    font-size: 12.5px;
  }}
  .section-content pre code {{ background: none; padding: 0; }}
  .section-content table {{
    border-collapse: collapse;
    margin: 10px 0;
    font-size: 12.5px;
    max-width: 100%;
  }}
  .section-content table th, .section-content table td {{
    border: 1px solid var(--border);
    padding: 4px 8px;
    vertical-align: top;
  }}
  .section-content table th {{ background: var(--bg-alt); }}
  .section-content blockquote {{
    border-left: 3px solid var(--accent);
    background: var(--accent-bg);
    margin: 8px 0;
    padding: 6px 12px;
  }}
  .section-content a {{ color: var(--link); }}

  /* Per-element commentable wrapper styling */
  [data-elt-id] {{
    position: relative;
  }}
  [data-elt-id]:hover {{
    background: rgba(255, 240, 154, 0.18);
  }}
  [data-elt-id].active-target {{
    background: rgba(255, 240, 154, 0.45);
  }}
  [data-elt-id].flash {{
    animation: flash 1.8s ease-out;
  }}
  @keyframes flash {{
    0%   {{ background: var(--highlight); }}
    100% {{ background: transparent; }}
  }}

  /* Per-element "comment +N" affordance — absolutely positioned at right margin */
  .elt-handle {{
    position: absolute;
    right: -28px;
    top: 0;
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 1px 6px;
    border-radius: 10px;
    background: white;
    border: 1px solid var(--border);
    color: var(--muted);
    font-size: 10px;
    font-weight: 600;
    cursor: pointer;
    opacity: 0;
    transition: opacity 0.08s;
    user-select: none;
    font-family: ui-monospace, monospace;
    z-index: 4;
    white-space: nowrap;
  }}
  [data-elt-id]:hover > .elt-handle,
  tr[data-elt-id]:hover .elt-handle.row-handle,
  .elt-handle.has-comments,
  .elt-handle.active-target {{
    opacity: 1;
  }}
  .elt-handle:hover {{
    background: var(--accent);
    color: white;
    border-color: var(--accent);
  }}
  .elt-handle.has-comments {{
    background: var(--warn-bg);
    color: var(--warn);
    border-color: var(--note-border);
  }}
  .elt-handle .count {{ font-weight: 700; }}
  li > .elt-handle {{ right: -32px; }}
  /* Row handle lives inside the last <td> of the row, positioned at the row's right edge. */
  td.has-row-handle {{ position: relative; }}
  .elt-handle.row-handle {{
    right: -32px;
    top: 50%;
    transform: translateY(-50%);
  }}

  /* Commentary column. Cards inside are absolutely-positioned so each one
     aligns vertically with its target element in .section-content. The
     column's min-height is set by JS once cards are placed; CSS grid then
     stretches the whole row to match (so long comments push content down). */
  .commentary-col {{
    border-left: 1px solid var(--border);
    padding-left: 12px;
    min-width: 0;
    position: relative;
  }}
  .commentary-col .col-header {{
    font-size: 10px;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    display: flex;
    align-items: center;
    gap: 6px;
    margin-bottom: 4px;
  }}
  .commentary-col .col-header .set-name {{
    color: var(--fg);
    font-weight: 600;
    text-transform: none;
    letter-spacing: 0;
    font-size: 11px;
  }}
  .comment-card {{
    background: var(--note-bg);
    border: 1px solid var(--note-border);
    border-radius: 5px;
    padding: 6px 8px;
    font-size: 12.5px;
    position: absolute;
    left: 12px;
    right: 4px;
    transition: top 0.12s ease-out;
  }}
  .comment-card.readonly {{
    background: #f4f3ee;
    border-color: var(--border);
    color: #444;
  }}
  .comment-card .ref-chip {{
    display: inline-block;
    background: var(--accent-bg);
    color: var(--link);
    padding: 0 6px;
    border-radius: 8px;
    font-size: 10px;
    font-family: ui-monospace, monospace;
    cursor: pointer;
    border: 1px solid transparent;
  }}
  .comment-card .ref-chip:hover {{
    background: var(--accent);
    color: white;
  }}
  .comment-card .ref-chip.section-ref {{
    background: var(--bg-alt);
    font-style: italic;
  }}
  .comment-card .delete-btn {{
    position: absolute;
    top: 4px;
    right: 4px;
    background: none;
    border: none;
    color: var(--muted);
    cursor: pointer;
    font-size: 13px;
    padding: 0 4px;
    line-height: 1;
    border-radius: 50%;
  }}
  .comment-card .delete-btn:hover {{
    color: white;
    background: #c62828;
  }}
  .comment-card textarea {{
    width: 100%;
    min-height: 60px;
    border: 1px solid var(--note-border);
    background: white;
    border-radius: 3px;
    padding: 4px 6px;
    font: inherit;
    font-size: 12.5px;
    resize: vertical;
    margin-top: 4px;
    outline: none;
  }}
  .comment-card textarea:focus {{ border-color: var(--accent); }}
  .comment-card .rendered {{
    margin-top: 4px;
    font-size: 12.5px;
  }}
  .comment-card .rendered p {{ margin: 4px 0; }}
  .comment-card .rendered ul, .comment-card .rendered ol {{ margin: 4px 0; padding-left: 18px; }}
  .comment-card .meta {{
    color: var(--muted);
    font-size: 10px;
    margin-top: 4px;
    display: flex;
    justify-content: space-between;
  }}
  .comment-card .toolbar {{
    display: flex;
    gap: 4px;
    margin-top: 4px;
  }}
  .comment-card .toolbar button {{
    font-size: 10.5px;
    padding: 2px 8px;
    border: 1px solid var(--border);
    background: white;
    border-radius: 3px;
    cursor: pointer;
    font-family: inherit;
  }}
  .comment-card .toolbar button:hover {{ background: var(--accent-bg); }}
  .commentary-empty {{
    color: var(--muted);
    font-size: 11px;
    font-style: italic;
    opacity: 0.6;
  }}

  /* Cross-reference link styling (inside notes) */
  .xref {{
    color: var(--link);
    text-decoration: underline;
    text-decoration-style: dotted;
    text-decoration-color: var(--accent);
    text-underline-offset: 2px;
    cursor: pointer;
  }}
  .xref:hover {{
    background: var(--accent-bg);
    text-decoration-style: solid;
  }}
  .xref.broken {{
    color: #c62828;
    text-decoration-color: #c62828;
  }}

  /* Search results */
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
  .search-hit .ctx {{ color: var(--muted); margin-left: 4px; }}
  mark {{ background: var(--highlight); padding: 0 1px; }}

  /* TOC sidebar */
  .toc-wrap {{
    background: var(--bg-alt);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 8px 12px;
    margin: 8px 0 16px;
    font-size: 12.5px;
  }}
  .toc-wrap summary {{ cursor: pointer; font-weight: 600; }}
  .toc-wrap .toc-grid {{
    margin-top: 8px;
    columns: 2;
    column-gap: 18px;
  }}
  .toc-wrap a {{
    display: block;
    text-decoration: none;
    color: var(--link);
    padding: 1px 0;
    break-inside: avoid;
  }}
  .toc-wrap a:hover {{ color: var(--accent); text-decoration: underline; }}
  .toc-wrap a[data-lvl="1"] {{ font-weight: 600; }}
  .toc-wrap a[data-lvl="2"] {{ padding-left: 8px; }}
  .toc-wrap a[data-lvl="3"] {{ padding-left: 16px; }}
  .toc-wrap a[data-lvl="4"] {{ padding-left: 24px; font-size: 12px; }}
  .toc-wrap a[data-lvl="5"], .toc-wrap a[data-lvl="6"] {{ padding-left: 32px; font-size: 11.5px; color: var(--muted); }}

  /* Manifest page */
  .manifest-table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
  }}
  .manifest-table th, .manifest-table td {{
    border: 1px solid var(--border);
    padding: 4px 8px;
    vertical-align: top;
    text-align: left;
  }}
  .manifest-table th {{ background: var(--bg-alt); position: sticky; top: 56px; }}
  .manifest-table tr:hover {{ background: var(--accent-bg); }}
  .manifest-table .ref {{
    font-family: ui-monospace, monospace;
    font-size: 11px;
    white-space: nowrap;
  }}

  @media (max-width: 1100px) {{
    .section-row {{ grid-template-columns: 1fr !important; }}
    .commentary-col {{ border-left: none; border-top: 1px solid var(--border); padding-left: 0; padding-top: 8px; min-height: 0 !important; }}
    .commentary-col .comment-card {{ position: static !important; left: auto !important; right: auto !important; margin-bottom: 6px; }}
    .elt-handle {{ right: 0; top: -22px; }}
  }}
</style>
</head>
<body>

<header>
  <h1>WebPKI Policy Reference</h1>
  <div class="nav-row">
    <span class="nav-label">Docs:</span>
    {src_nav}
    <button class="navbtn" data-route="#manifest" title="All commentable IDs">Manifest</button>
    <div class="controls">
      <input id="search" type="search" placeholder="Search docs (Enter to run)…">
      <button id="exportBtn" title="Download your comments as JSON">Export</button>
      <button id="importFileBtn" title="Load a comments JSON as a read-only column">Load file…</button>
      <button id="importUrlBtn" title="Load a comments JSON from a URL">Load URL…</button>
      <input id="importInput" type="file" accept="application/json" style="display:none">
      <a class="repo-link" href="https://github.com/mcpherrinm/webpki-policy-docs" target="_blank" rel="noopener" title="View source on GitHub">GitHub</a>
    </div>
  </div>
  <div id="loadedSetsBar" class="loaded-sets-bar" style="display:none"></div>
</header>

<main id="content"></main>

<script>
{marked_js}
</script>

<script>
"use strict";

// ===== Embedded build-time data =====
const SRC_DATA   = {src_data_json};
const SRC_KEYS   = {src_keys_json};
const SRC_LABELS = {src_labels_json};
const MANIFEST   = {manifest_json};  // [{{ref, doc, section, kind, ord, title, snippet}}]

// ===== marked.js configuration =====
marked.setOptions({{ gfm: true, breaks: false }});

// ===== Comment storage (localStorage) =====
//
// Schema (current = v2):
//   webpki-comments::v2::<docKey>::<eltId> → JSON array of comments
//     [{{id, text, createdAt, updatedAt}}]
//   webpki-loaded-sets::v1 → JSON array of {{id, name, source, comments: {{<docKey>/<eltId>: [...] }} }}

const NS = "webpki-comments::v2::";
const LOADED_SETS_KEY = "webpki-loaded-sets::v1";

function commentsKey(docKey, eltId) {{ return NS + docKey + "::" + eltId; }}

function getComments(docKey, eltId) {{
  try {{
    const raw = localStorage.getItem(commentsKey(docKey, eltId));
    if (!raw) return [];
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr : [];
  }} catch (e) {{ return []; }}
}}

function setComments(docKey, eltId, arr) {{
  try {{
    if (!arr || arr.length === 0) {{
      localStorage.removeItem(commentsKey(docKey, eltId));
    }} else {{
      localStorage.setItem(commentsKey(docKey, eltId), JSON.stringify(arr));
    }}
  }} catch (e) {{ console.error(e); }}
}}

function addComment(docKey, eltId, text) {{
  const arr = getComments(docKey, eltId);
  const c = {{
    id: "c-" + Date.now().toString(36) + "-" + Math.random().toString(36).substring(2, 5),
    text: text || "",
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  }};
  arr.push(c);
  setComments(docKey, eltId, arr);
  return c;
}}

function updateCommentText(docKey, eltId, commentId, newText) {{
  const arr = getComments(docKey, eltId);
  const i = arr.findIndex((c) => c.id === commentId);
  if (i < 0) return;
  arr[i].text = newText;
  arr[i].updatedAt = new Date().toISOString();
  setComments(docKey, eltId, arr);
}}

function deleteComment(docKey, eltId, commentId) {{
  const arr = getComments(docKey, eltId).filter((c) => c.id !== commentId);
  setComments(docKey, eltId, arr);
}}

function allCommentsForDoc(docKey) {{
  const out = {{}};
  const prefix = NS + docKey + "::";
  for (let i = 0; i < localStorage.length; i++) {{
    const k = localStorage.key(i);
    if (k && k.startsWith(prefix)) {{
      try {{
        const eltId = k.substring(prefix.length);
        out[eltId] = JSON.parse(localStorage.getItem(k));
      }} catch (e) {{}}
    }}
  }}
  return out;
}}

function allCommentsAllDocs() {{
  const out = {{}};
  for (let i = 0; i < localStorage.length; i++) {{
    const k = localStorage.key(i);
    if (k && k.startsWith(NS)) {{
      const rest = k.substring(NS.length);
      const sep = rest.indexOf("::");
      if (sep < 0) continue;
      const docKey = rest.substring(0, sep);
      const eltId = rest.substring(sep + 2);
      try {{
        if (!out[docKey]) out[docKey] = {{}};
        out[docKey][eltId] = JSON.parse(localStorage.getItem(k));
      }} catch (e) {{}}
    }}
  }}
  return out;
}}

// ===== Loaded read-only commentary sets =====
let LOADED_SETS = [];

function loadLoadedSetsFromStorage() {{
  try {{
    const raw = localStorage.getItem(LOADED_SETS_KEY);
    if (!raw) return [];
    const a = JSON.parse(raw);
    return Array.isArray(a) ? a : [];
  }} catch (e) {{ return []; }}
}}

function saveLoadedSetsToStorage() {{
  try {{ localStorage.setItem(LOADED_SETS_KEY, JSON.stringify(LOADED_SETS)); }}
  catch (e) {{ console.error(e); }}
}}

function normalizeImportedPayload(obj) {{
  // Accept two shapes:
  //  v2 export: {{version: 2, comments: {{<docKey>: {{<eltId>: [comments]}}}}}}
  //  flat:      {{<docKey>: {{<eltId>: [comments or string]}}}}
  let src = {{}};
  if (obj && typeof obj === "object") {{
    if (obj.comments && typeof obj.comments === "object") src = obj.comments;
    else src = obj;
  }}
  const clean = {{}};
  for (const docKey of Object.keys(src)) {{
    const inner = src[docKey];
    if (!inner || typeof inner !== "object") continue;
    clean[docKey] = {{}};
    for (const eltId of Object.keys(inner)) {{
      const v = inner[eltId];
      if (Array.isArray(v)) {{
        clean[docKey][eltId] = v.filter((c) => c && typeof c.text === "string");
      }} else if (typeof v === "string" && v.trim() !== "") {{
        clean[docKey][eltId] = [{{ id: "imp", text: v, createdAt: "", updatedAt: "" }}];
      }}
    }}
  }}
  return clean;
}}

function deriveSetName(source) {{
  if (!source) return "Imported";
  let name = source;
  try {{ name = decodeURIComponent(name); }} catch (e) {{}}
  name = name.replace(/[?#].*$/, "").replace(/\/$/, "");
  const slash = name.lastIndexOf("/");
  if (slash >= 0) name = name.substring(slash + 1);
  return name.replace(/\.json$/i, "") || "Imported";
}}

function addLoadedSet(name, payload, source) {{
  const comments = normalizeImportedPayload(payload);
  const id = "set-" + Date.now().toString(36) + "-" + Math.random().toString(36).substring(2, 5);
  LOADED_SETS.push({{ id, name, source: source || "", comments }});
  saveLoadedSetsToStorage();
  applySideCountVars();
  renderLoadedSetsBar();
  rerouteSoft();
}}

function removeLoadedSet(id) {{
  LOADED_SETS = LOADED_SETS.filter((s) => s.id !== id);
  saveLoadedSetsToStorage();
  applySideCountVars();
  renderLoadedSetsBar();
  rerouteSoft();
}}

function applySideCountVars() {{
  const n = LOADED_SETS.length + 1;
  document.body.style.setProperty("--side-count", n);
  let w = 340;
  if (n === 2) w = 280;
  else if (n === 3) w = 240;
  else if (n >= 4) w = 200;
  document.body.style.setProperty("--side-width", w + "px");
}}

function renderLoadedSetsBar() {{
  const bar = document.getElementById("loadedSetsBar");
  if (!bar) return;
  if (LOADED_SETS.length === 0) {{
    bar.style.display = "none";
    bar.innerHTML = "";
    return;
  }}
  bar.style.display = "flex";
  let h = '<span class="label">Columns:</span>';
  h += '<span class="loaded-set-chip local">Local (editable)</span>';
  for (const s of LOADED_SETS) {{
    let count = 0;
    for (const dk of Object.keys(s.comments)) {{
      for (const eid of Object.keys(s.comments[dk])) count += s.comments[dk][eid].length;
    }}
    const title = count + " comment(s)" + (s.source ? " from " + s.source : "");
    h += '<span class="loaded-set-chip" title="' + escapeAttr(title) + '">' +
         escapeHtml(s.name) +
         ' <button class="remove-btn" data-remove-set="' + escapeAttr(s.id) + '">×</button></span>';
  }}
  bar.innerHTML = h;
}}

// ===== Helpers =====
function escapeHtml(s) {{
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}}
function escapeAttr(s) {{ return escapeHtml(s); }}

// ===== Element-ID computation (must match Python parser) =====
//
// Walking rules:
//   - On heading: compute section id from text; reset p/li/tr counters.
//   - On <p>: bump p.
//   - On <li>: bump li (we visit every <li> including nested).
//   - On <tr> in <tbody>: bump tr.
//
// Section id from heading text:
//   numeric prefix "N(.N)*" stripped to that;  else slug of the whole heading.
//   collisions within a doc get "-2", "-3" suffix.

function computeSectionFromHeading(text, seenMap) {{
  const t = text.trim();
  const m = t.match(/^(\d+(?:\.\d+)*)\.?(?:\s|$)/);
  let sid;
  if (m) sid = m[1];
  else sid = slugify(t);
  const n = (seenMap[sid] || 0) + 1;
  seenMap[sid] = n;
  if (n > 1) sid = sid + "-" + n;
  return sid;
}}

function slugify(s) {{
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").substring(0, 48) || "section";
}}

// ===== Document rendering =====
//
// Strategy: each top-level section (per heading) becomes its own .section-row
// grid (content + commentary columns). To get this layout while letting marked.js
// render naturally, we:
//   1. Split the markdown into chunks at each heading.
//   2. For each chunk: render with marked, wrap in .section-content, build a
//      commentary column. Append to a doc-page container.

function splitMarkdownAtHeadings(md) {{
  // Returns [{{heading: "...", level: N|null, body: "..."}}]; first chunk has no heading.
  const lines = md.split("\n");
  const chunks = [];
  let cur = {{ heading: null, level: null, body: [] }};
  let inCode = false;
  let inFront = false;
  for (let i = 0; i < lines.length; i++) {{
    const line = lines[i];
    // Skip YAML frontmatter at top
    if (i === 0 && line.trim() === "---") {{ inFront = true; cur.body.push(line); continue; }}
    if (inFront) {{
      cur.body.push(line);
      if (line.trim() === "---") inFront = false;
      continue;
    }}
    const s = line.trimStart();
    if (s.startsWith("```") || s.startsWith("~~~")) inCode = !inCode;
    if (!inCode) {{
      const m = line.match(/^(#{{1,6}})\s+(.+?)\s*$/);
      if (m) {{
        chunks.push(cur);
        cur = {{ heading: m[2].trim(), level: m[1].length, body: [line] }};
        continue;
      }}
    }}
    cur.body.push(line);
  }}
  chunks.push(cur);
  return chunks.map((c) => ({{ heading: c.heading, level: c.level, body: c.body.join("\n") }}));
}}

function renderDocPage(docKey) {{
  const doc = SRC_DATA[docKey];
  const page = document.createElement("div");
  page.className = "doc-page";
  page.dataset.docKey = docKey;
  page.innerHTML =
    '<h1 class="doc-title">' + escapeHtml(SRC_LABELS[docKey]) + '</h1>' +
    '<div class="doc-meta">Rendered from ' + escapeHtml(doc.filename) +
    ' · ' + (doc.section_count || 0) + ' sections · ' + (doc.elt_count || 0) + ' commentable elements · ' +
    'Refs look like <code>' + escapeHtml(docKey) + '/&lt;section&gt;</code> or ' +
    '<code>' + escapeHtml(docKey) + '/&lt;section&gt;/p3</code> ' +
    '(e.g. in code: <code>// webpki:' + escapeHtml(docKey) + '/&lt;section&gt;/p3</code>).</div>';

  // Build TOC from headings while we render.
  const tocWrap = document.createElement("details");
  tocWrap.className = "toc-wrap";
  tocWrap.open = false;
  tocWrap.innerHTML = '<summary>Table of contents</summary><div class="toc-grid"></div>';
  page.appendChild(tocWrap);
  const tocBox = tocWrap.querySelector(".toc-grid");

  const chunks = splitMarkdownAtHeadings(doc.raw);
  const seenSections = {{}};

  let isFirst = true;
  for (const chunk of chunks) {{
    // Skip empty preamble (no heading and no body) — common when doc starts with H1.
    if (!chunk.heading && !chunk.body.trim()) continue;
    const row = document.createElement("div");
    row.className = "section-row" + (isFirst ? " first" : "");
    isFirst = false;

    const content = document.createElement("div");
    content.className = "section-content";
    if (!chunk.heading) content.classList.add("preamble-block");

    const html = marked.parse(chunk.body || "");
    content.innerHTML = html;

    // Compute section id for this chunk.
    let sectionId;
    if (chunk.heading) {{
      sectionId = computeSectionFromHeading(chunk.heading, seenSections);
    }} else {{
      sectionId = "_preamble";
    }}
    row.dataset.sectionId = sectionId;

    // Assign ids to elements within content.
    annotateElementsWithIds(content, sectionId, docKey);

    // Anchor for direct linking to this section (heading itself, if any).
    const h = content.querySelector("h1, h2, h3, h4, h5, h6");
    if (h) {{
      h.id = "sec-" + sectionId.replace(/\./g, "-").replace(/\//g, "_");
      h.dataset.eltId = sectionId;
      h.dataset.eltKind = "section";

      const handle = makeEltHandle(docKey, sectionId, "section");
      h.appendChild(handle);

      // Add to TOC
      const link = document.createElement("a");
      link.href = "#" + docKey + "/" + sectionId;
      link.textContent = chunk.heading;
      link.dataset.lvl = chunk.level || 1;
      tocBox.appendChild(link);
    }}

    // Add commentary column(s)
    row.appendChild(content);
    row.appendChild(makeCommentaryColumn({{ kind: "local", docKey, sectionId }}));
    for (const set of LOADED_SETS) {{
      row.appendChild(makeCommentaryColumn({{ kind: "loaded", docKey, sectionId, set }}));
    }}

    page.appendChild(row);
  }}

  return page;
}}

function annotateElementsWithIds(content, sectionId, docKey) {{
  // Must match Python parser counting rules:
  //   p  → top-level paragraphs only (skip <p> inside <li>, <blockquote>, <td>, <th>)
  //   li → every <li>, nested or not
  //   tr → every <tr> inside <tbody>
  let pCount = 0, liCount = 0, trCount = 0;
  const walker = document.createTreeWalker(content, NodeFilter.SHOW_ELEMENT);
  let node;
  while ((node = walker.nextNode())) {{
    const tag = node.tagName.toLowerCase();
    if (tag === "p") {{
      // Skip if any ancestor is a list item / blockquote / table cell.
      let skip = false;
      let p = node.parentElement;
      while (p && p !== content) {{
        const t = p.tagName.toLowerCase();
        if (t === "li" || t === "blockquote" || t === "td" || t === "th") {{
          skip = true; break;
        }}
        p = p.parentElement;
      }}
      if (skip) continue;
      pCount++;
      const eid = sectionId + "/p" + pCount;
      node.dataset.eltId = eid;
      node.dataset.eltKind = "p";
      node.appendChild(makeEltHandle(docKey, eid, "p"));
    }} else if (tag === "li") {{
      liCount++;
      const eid = sectionId + "/li" + liCount;
      node.dataset.eltId = eid;
      node.dataset.eltKind = "li";
      node.appendChild(makeEltHandle(docKey, eid, "li"));
    }} else if (tag === "tr" && node.closest("tbody")) {{
      trCount++;
      const eid = sectionId + "/tr" + trCount;
      node.dataset.eltId = eid;
      node.dataset.eltKind = "tr";
      const lastTd = node.lastElementChild;
      if (lastTd) {{
        lastTd.classList.add("has-row-handle");
        const handle = makeEltHandle(docKey, eid, "tr");
        handle.classList.add("row-handle");
        lastTd.appendChild(handle);
      }}
    }}
  }}
}}

function commentCount(docKey, eltId) {{
  let total = getComments(docKey, eltId).length;
  for (const s of LOADED_SETS) {{
    const dk = s.comments[docKey];
    if (dk && dk[eltId]) total += dk[eltId].length;
  }}
  return total;
}}

function makeEltHandle(docKey, eltId, kind) {{
  const a = document.createElement("span");
  a.className = "elt-handle";
  a.dataset.docKey = docKey;
  a.dataset.eltId = eltId;
  a.dataset.kind = kind;
  refreshHandle(a);
  return a;
}}

function refreshHandle(a) {{
  if (!a) return;
  const n = commentCount(a.dataset.docKey, a.dataset.eltId);
  const ref = formatRefSymbol(a.dataset.eltId);
  if (n > 0) {{
    a.classList.add("has-comments");
    a.innerHTML = '<span class="count">' + n + '</span> ' + escapeHtml(ref);
    a.title = n + " comment(s) on " + a.dataset.docKey + "/" + a.dataset.eltId;
  }} else {{
    a.classList.remove("has-comments");
    a.innerHTML = '+ ' + escapeHtml(ref);
    a.title = "Add comment on " + a.dataset.docKey + "/" + a.dataset.eltId;
  }}
}}

// Symbolic ref including section.
//   1.2.1            → "§1.2.1"
//   1.2.1/p3         → "§1.2.1 ¶3"
//   1.2.1/li5        → "§1.2.1 •5"
//   1.2.1/tr2        → "§1.2.1 □2"
function formatRefSymbol(eltId) {{
  const slash = eltId.indexOf("/");
  if (slash < 0) return "§" + eltId;
  const section = eltId.substring(0, slash);
  const rest = eltId.substring(slash + 1);
  const m = rest.match(/^(p|li|tr)(\d+)$/);
  if (!m) return "§" + section + " " + rest;
  const sym = m[1] === "p" ? "¶" : (m[1] === "li" ? "•" : "□");
  return "§" + section + " " + sym + m[2];
}}

function refreshAllHandlesFor(docKey, eltId) {{
  document.querySelectorAll('.elt-handle[data-doc-key="' + cssEscape(docKey) + '"][data-elt-id="' + cssEscape(eltId) + '"]').forEach(refreshHandle);
}}

function cssEscape(s) {{
  return String(s).replace(/(["\\#.:/])/g, "\\$&");
}}

// ===== Commentary column =====
function makeCommentaryColumn({{ kind, docKey, sectionId, set }}) {{
  const col = document.createElement("div");
  col.className = "commentary-col";
  col.dataset.docKey = docKey;
  col.dataset.sectionId = sectionId;
  if (kind === "local") {{
    col.dataset.colKind = "local";
    col.innerHTML = '<div class="col-header"><span class="set-name">Local</span> <span style="opacity:0.7">editable</span></div>';
  }} else {{
    col.dataset.colKind = "loaded";
    col.dataset.setId = set.id;
    col.innerHTML = '<div class="col-header"><span class="set-name">' + escapeHtml(set.name) + '</span> <span style="opacity:0.7">read-only</span></div>';
  }}
  renderCommentaryColumn(col);
  return col;
}}

function renderCommentaryColumn(col) {{
  const docKey = col.dataset.docKey;
  const sectionId = col.dataset.sectionId;
  const isLocal = col.dataset.colKind === "local";
  const setId = col.dataset.setId;
  const set = setId ? LOADED_SETS.find((s) => s.id === setId) : null;

  // Find all elements in this section that have comments in this col's source.
  let source;
  if (isLocal) {{
    source = allCommentsForDoc(docKey);
  }} else {{
    source = set ? (set.comments[docKey] || {{}}) : {{}};
  }}
  const eltIds = Object.keys(source).filter((eid) => eid === sectionId || eid.startsWith(sectionId + "/"));
  // sort: section itself first, then by elt order (p < li < tr) and by ordinal
  eltIds.sort(compareEltIds);

  // Remove old comment cards from this column (preserve header)
  const header = col.querySelector(".col-header");
  col.innerHTML = "";
  if (header) col.appendChild(header);

  if (eltIds.length === 0) {{
    if (isLocal) {{
      const hint = document.createElement("div");
      hint.className = "commentary-empty";
      hint.textContent = "Hover content → click + to comment.";
      col.appendChild(hint);
    }}
  }} else {{
    for (const eid of eltIds) {{
      const comments = source[eid] || [];
      for (const c of comments) {{
        col.appendChild(renderCommentCard({{
          docKey, eltId: eid, comment: c, readonly: !isLocal,
        }}));
      }}
    }}
  }}
}}

// Align each comment card vertically with its target element. Cards are
// absolutely positioned within their commentary column; we set `top` so it
// matches the target's offset within the section row, then resolve overlaps
// by pushing later cards down. The column's min-height is set so CSS grid
// stretches the whole row when comments are collectively taller than content.
function alignSectionRowComments(row) {{
  if (!row || !row.querySelector) return;
  const content = row.querySelector(".section-content");
  if (!content) return;
  // Skip on narrow viewports where the layout collapses to a single column.
  if (window.innerWidth <= 1100) {{
    row.querySelectorAll(".commentary-col").forEach((col) => {{ col.style.minHeight = ""; }});
    return;
  }}
  const rowRect = row.getBoundingClientRect();
  const cols = row.querySelectorAll(".commentary-col");
  cols.forEach((col) => {{
    const cards = Array.from(col.querySelectorAll(".comment-card"));
    if (cards.length === 0) {{
      col.style.minHeight = "";
      return;
    }}
    const placed = cards.map((card) => {{
      const target = content.querySelector('[data-elt-id="' + cssEscape(card.dataset.eltId) + '"]');
      const targetTop = target ? (target.getBoundingClientRect().top - rowRect.top) : 0;
      return {{ card, targetTop }};
    }});
    placed.sort((a, b) => a.targetTop - b.targetTop);
    let prevBottom = 0;
    const gap = 6;
    for (const p of placed) {{
      const top = Math.max(p.targetTop, prevBottom);
      p.card.style.top = top + "px";
      prevBottom = top + p.card.offsetHeight + gap;
    }}
    col.style.minHeight = prevBottom + "px";
  }});
}}

function alignAllSectionRows() {{
  document.querySelectorAll(".section-row").forEach(alignSectionRowComments);
}}

let _alignScheduled = false;
function scheduleAlign() {{
  if (_alignScheduled) return;
  _alignScheduled = true;
  requestAnimationFrame(() => {{
    _alignScheduled = false;
    alignAllSectionRows();
  }});
}}

let _resizeTimer = null;
window.addEventListener("resize", () => {{
  clearTimeout(_resizeTimer);
  _resizeTimer = setTimeout(alignAllSectionRows, 80);
}});

function compareEltIds(a, b) {{
  // section itself sorts first; then by kind p < li < tr; then by ordinal.
  function key(s) {{
    const slash = s.indexOf("/");
    if (slash < 0) return [0, 0];
    const rest = s.substring(slash + 1);
    const m = rest.match(/^(p|li|tr)(\d+)$/);
    if (!m) return [3, 0];
    const ord = parseInt(m[2], 10);
    const kindOrder = m[1] === "p" ? 1 : (m[1] === "li" ? 2 : 3);
    return [kindOrder, ord];
  }}
  const ka = key(a), kb = key(b);
  return ka[0] - kb[0] || ka[1] - kb[1];
}}

function renderCommentCard({{ docKey, eltId, comment, readonly }}) {{
  const card = document.createElement("div");
  card.className = "comment-card" + (readonly ? " readonly" : "");
  card.dataset.docKey = docKey;
  card.dataset.eltId = eltId;
  card.dataset.commentId = comment.id;
  const isSection = !eltId.includes("/");
  const refLabel = formatRefSymbol(eltId);
  let html = '<div>' +
    '<span class="ref-chip' + (isSection ? ' section-ref' : '') + '" data-jump-elt="' + escapeAttr(eltId) + '" title="Jump to element">' +
      escapeHtml(refLabel) +
    '</span>';
  if (!readonly) {{
    html += '<button class="delete-btn" title="Delete this comment">×</button>';
  }}
  html += '</div>';

  // Body: read-only renders markdown; editable shows textarea + rendered preview
  if (readonly) {{
    html += '<div class="rendered">' + renderCommentMarkdown(comment.text) + '</div>';
  }} else {{
    html += '<textarea class="cmt-text" placeholder="Markdown. Refs: [label](#doc/sec/p3), [[doc/sec/p3]], or &quot;CABF BR §3.2 ¶1&quot;">' +
            escapeHtml(comment.text || "") + '</textarea>';
    html += '<div class="rendered"></div>';
    html += '<div class="meta"><span class="save-status"></span><span>' + (comment.updatedAt ? new Date(comment.updatedAt).toLocaleString() : "") + '</span></div>';
  }}
  card.innerHTML = html;

  if (!readonly) {{
    // initial render preview
    const ta = card.querySelector(".cmt-text");
    const rendered = card.querySelector(".rendered");
    rendered.innerHTML = renderCommentMarkdown(ta.value);
  }}
  return card;
}}

// ===== Markdown rendering + cross-reference linkification =====

function renderCommentMarkdown(md) {{
  if (!md) return "";
  let html = marked.parseInline(md.replace(/\n\n+/g, "<br>"));
  // marked.parseInline doesn't do block-level; for short notes that's fine,
  // but we also want lists/paras. Use full parse if there are blank lines.
  if (md.indexOf("\n\n") >= 0 || md.indexOf("\n- ") >= 0 || md.indexOf("\n* ") >= 0) {{
    html = marked.parse(md);
  }}
  // Linkify cross-refs in the resulting HTML's text nodes.
  const tmp = document.createElement("div");
  tmp.innerHTML = html;
  linkifyRefs(tmp);
  return tmp.innerHTML;
}}

// Patterns we recognise (in priority order):
//  1. [[<docKey>#<section>[/<elt>]]]    — wiki-style explicit ref
//  2. <DocLabel> §<section>[ ¶<n>|/<elt>]    — natural form
//  3. <docKey>#<section>[/<elt>]        — bare ref
function buildXrefPatterns() {{
  const labels = [];
  for (const k of SRC_KEYS) {{
    labels.push({{ name: SRC_LABELS[k], key: k }});
  }}
  // Sort by name length desc so longer names match first ("LE CP/CPS" before "LE")
  labels.sort((a, b) => b.name.length - a.name.length);
  const escName = (s) => s.replace(/[.*+?^${{}}()|[\]\\\/]/g, "\\$&");
  const labelAlt = labels.map((l) => escName(l.name)).join("|");
  const docKeyAlt = SRC_KEYS.map(escName).join("|");
  return [
    {{ // [[key/section[/elt]]] (wiki style)
      re: /\[\[\s*(\w+)\/([^\s\]\/]+)(?:\/([a-z]+\d+))?\s*\]\]/g,
      build: (m) => ({{
        href: "#" + m[1] + "/" + m[2] + (m[3] ? "/" + m[3] : ""),
        text: m[1] + "/" + m[2] + (m[3] ? "/" + m[3] : ""),
        docKey: m[1], eltId: m[2] + (m[3] ? "/" + m[3] : ""),
      }}),
    }},
    {{ // Natural: "CABF BR §7.1.2.10.2 ¶3" / " /li3" / " /tr2"
      re: new RegExp("\\b(" + labelAlt + ")\\s+§(\\d+(?:\\.\\d+)*)" +
                     "(?:\\s+¶(\\d+)|/(p\\d+|li\\d+|tr\\d+))?", "g"),
      build: (m) => {{
        const label = labels.find((l) => l.name === m[1]);
        const docKey = label ? label.key : m[1];
        const sec = m[2];
        const elt = m[3] ? "p" + m[3] : (m[4] || "");
        const eid = sec + (elt ? "/" + elt : "");
        return {{ href: "#" + docKey + "/" + eid, text: m[0], docKey, eltId: eid }};
      }},
    }},
    {{ // bare webpki:key/section[/elt] — for tooling-style refs
      re: new RegExp("\\bwebpki:(" + docKeyAlt + ")/([\\w.\\-]+)(?:/([a-z]+\\d+))?", "g"),
      build: (m) => {{
        const eid = m[2] + (m[3] ? "/" + m[3] : "");
        return {{ href: "#" + m[1] + "/" + eid, text: m[0], docKey: m[1], eltId: eid }};
      }},
    }},
  ];
}}

let _XREF_PATTERNS = null;
function xrefPatterns() {{
  if (!_XREF_PATTERNS) _XREF_PATTERNS = buildXrefPatterns();
  return _XREF_PATTERNS;
}}

function isValidRef(docKey, eltId) {{
  if (!SRC_DATA[docKey]) return false;
  // section-only: check sections list
  const flat = SRC_DATA[docKey].section_ids || [];
  if (flat.indexOf(eltId) >= 0) return true;
  // check element manifest
  const elts = SRC_DATA[docKey].elt_ids || [];
  return elts.indexOf(eltId) >= 0;
}}

function linkifyRefs(root) {{
  const patterns = xrefPatterns();
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {{
    acceptNode: (n) => {{
      let p = n.parentNode;
      while (p && p !== root) {{
        if (p.tagName === "A" || p.tagName === "CODE" || p.tagName === "PRE") return NodeFilter.FILTER_REJECT;
        p = p.parentNode;
      }}
      return NodeFilter.FILTER_ACCEPT;
    }},
  }});
  const nodes = [];
  let cur;
  while ((cur = walker.nextNode())) nodes.push(cur);
  for (const tn of nodes) {{
    const text = tn.nodeValue;
    if (!text || text.length < 3) continue;
    const matches = [];
    for (let i = 0; i < patterns.length; i++) {{
      const p = patterns[i];
      const re = new RegExp(p.re.source, p.re.flags);
      let m;
      while ((m = re.exec(text)) !== null) {{
        matches.push({{ index: m.index, len: m[0].length, link: p.build(m), order: i }});
      }}
    }}
    if (matches.length === 0) continue;
    matches.sort((a, b) => a.index - b.index || a.order - b.order);
    const kept = [];
    let lastEnd = -1;
    for (const m of matches) {{
      if (m.index >= lastEnd) {{ kept.push(m); lastEnd = m.index + m.len; }}
    }}
    const frag = document.createDocumentFragment();
    let pos = 0;
    for (const m of kept) {{
      if (m.index > pos) frag.appendChild(document.createTextNode(text.substring(pos, m.index)));
      const a = document.createElement("a");
      a.className = "xref";
      a.href = m.link.href;
      a.textContent = m.link.text;
      if (!isValidRef(m.link.docKey, m.link.eltId)) {{
        a.classList.add("broken");
        a.title = "Reference not found in build manifest";
      }}
      frag.appendChild(a);
      pos = m.index + m.len;
    }}
    if (pos < text.length) frag.appendChild(document.createTextNode(text.substring(pos)));
    tn.parentNode.replaceChild(frag, tn);
  }}
}}

// ===== Manifest page =====
function renderManifestPage() {{
  const page = document.createElement("div");
  page.innerHTML =
    '<h1 class="doc-title">ID Manifest</h1>' +
    '<div class="doc-meta">' + MANIFEST.length + ' commentable elements across ' + SRC_KEYS.length + ' documents. ' +
    'Use any <code>ref</code> below as a stable cross-reference in code comments or notes — e.g. ' +
    '<code>// webpki:cabf_br/7.1.2.10.2/p3</code>.</div>';
  const sw = document.createElement("div");
  sw.innerHTML = '<input id="manifest-filter" type="search" placeholder="Filter… (ref, title, snippet)" style="width:340px;padding:4px 8px;border:1px solid var(--border);border-radius:4px;margin-bottom:8px;">';
  page.appendChild(sw);
  const tbl = document.createElement("table");
  tbl.className = "manifest-table";
  tbl.innerHTML = '<thead><tr><th>Ref</th><th>Doc</th><th>Section</th><th>Kind</th><th>Snippet</th></tr></thead><tbody></tbody>';
  page.appendChild(tbl);
  const tb = tbl.querySelector("tbody");
  for (const r of MANIFEST) {{
    const tr = document.createElement("tr");
    tr.dataset.searchKey = (r.ref + " " + r.title + " " + r.snippet).toLowerCase();
    tr.innerHTML =
      '<td class="ref"><a href="#' + escapeAttr(r.doc) + '/' + escapeAttr(r.section + (r.kind === "section" ? "" : "/" + r.kind + r.ord)) + '">' + escapeHtml(r.ref) + '</a></td>' +
      '<td>' + escapeHtml(SRC_LABELS[r.doc] || r.doc) + '</td>' +
      '<td>' + escapeHtml(r.section + (r.title && r.title !== r.section ? " " + r.title : "")) + '</td>' +
      '<td>' + escapeHtml(r.kind === "section" ? "§" : r.kind) + (r.kind !== "section" ? r.ord : "") + '</td>' +
      '<td>' + escapeHtml(r.snippet || "") + '</td>';
    tb.appendChild(tr);
  }}
  // wire up filter
  setTimeout(() => {{
    const inp = page.querySelector("#manifest-filter");
    if (!inp) return;
    inp.addEventListener("input", () => {{
      const q = inp.value.toLowerCase().trim();
      tb.querySelectorAll("tr").forEach((row) => {{
        row.style.display = (!q || row.dataset.searchKey.indexOf(q) >= 0) ? "" : "none";
      }});
    }});
  }}, 0);
  return page;
}}

// ===== Routing =====
// Hashes:
//   #manifest                → manifest page
//   #<docKey>                → doc page top
//   #<docKey>#<sectionId>    → doc page, scroll to section
//   #<docKey>#<sectionId>/<eltKind><n>  → doc page, scroll to element

function navigateHash() {{
  const raw = window.location.hash.replace(/^#/, "");
  if (!raw) {{ renderRoute("cabf_br", null); return; }}
  if (raw === "manifest") {{ renderRoute("manifest", null); return; }}
  // Doc page with optional element ref. Split on first '/'.
  const slash = raw.indexOf("/");
  let docKey, eltId;
  if (slash < 0) {{
    docKey = raw;
    eltId = null;
  }} else {{
    docKey = raw.substring(0, slash);
    eltId = raw.substring(slash + 1);
  }}
  if (!SRC_DATA[docKey]) {{ renderRoute("cabf_br", null); return; }}
  renderRoute(docKey, eltId);
}}

function renderRoute(docKey, eltId) {{
  document.querySelectorAll(".navbtn").forEach((b) => b.classList.remove("active"));
  const main = document.getElementById("content");
  main.innerHTML = "";
  if (docKey === "manifest") {{
    document.querySelector('.navbtn[data-route="#manifest"]')?.classList.add("active");
    main.appendChild(renderManifestPage());
    return;
  }}
  const btn = document.querySelector('.navbtn[data-doc="' + cssEscape(docKey) + '"]');
  if (btn) btn.classList.add("active");
  main.appendChild(renderDocPage(docKey));
  scheduleAlign();
  // Scroll/flash target
  if (eltId) {{
    setTimeout(() => {{
      const target = document.querySelector('.doc-page[data-doc-key="' + cssEscape(docKey) + '"] [data-elt-id="' + cssEscape(eltId) + '"]');
      if (target) {{
        target.scrollIntoView({{ behavior: "smooth", block: "center" }});
        target.classList.add("flash", "active-target");
        setTimeout(() => target.classList.remove("flash", "active-target"), 2400);
      }}
    }}, 60);
  }} else {{
    window.scrollTo(0, 0);
  }}
}}

function rerouteSoft() {{
  // Re-render the current view (e.g., after loading a notes set so the new column appears).
  navigateHash();
}}

window.addEventListener("hashchange", navigateHash);

// ===== Event delegation =====

// Handle ref-chip clicks on mousedown — otherwise clicking the chip from
// inside a focused (and possibly empty) comment textarea would blur the
// textarea, run the focusout cleanup, and remove the chip before the click
// event fires. preventDefault keeps focus where it is until navigation
// re-renders the page.
document.addEventListener("mousedown", (e) => {{
  const jump = e.target.closest("[data-jump-elt]");
  if (!jump) return;
  e.preventDefault();
  const eid = jump.dataset.jumpElt;
  const card = jump.closest(".comment-card");
  const docKey = card?.dataset.docKey;
  if (docKey) window.location.hash = "#" + docKey + "/" + eid;
}});

document.addEventListener("click", (e) => {{
  // Nav button
  const navbtn = e.target.closest(".navbtn");
  if (navbtn) {{
    if (navbtn.dataset.route) {{
      window.location.hash = navbtn.dataset.route;
    }} else if (navbtn.dataset.doc) {{
      window.location.hash = "#" + navbtn.dataset.doc;
    }}
    return;
  }}

  // Remove loaded set
  const rm = e.target.closest("[data-remove-set]");
  if (rm) {{
    const id = rm.dataset.removeSet;
    if (confirm("Remove this comments column?")) removeLoadedSet(id);
    return;
  }}

  // Elt handle → add or focus comments
  const handle = e.target.closest(".elt-handle");
  if (handle) {{
    e.preventDefault();
    onHandleClicked(handle);
    return;
  }}

  // Jump from comment ref-chip to its element
  const jump = e.target.closest("[data-jump-elt]");
  if (jump) {{
    const eid = jump.dataset.jumpElt;
    const card = jump.closest(".comment-card");
    const docKey = card?.dataset.docKey;
    if (docKey) window.location.hash = "#" + docKey + "/" + eid;
    return;
  }}

  // Comment delete
  const del = e.target.closest(".comment-card .delete-btn");
  if (del) {{
    const card = del.closest(".comment-card");
    if (!card) return;
    if (!confirm("Delete this comment?")) return;
    const docKey = card.dataset.docKey;
    const eltId = card.dataset.eltId;
    const cid = card.dataset.commentId;
    deleteComment(docKey, eltId, cid);
    // Re-render the local commentary column that contains this card.
    const col = card.closest(".commentary-col");
    card.remove();
    if (col && !col.querySelector(".comment-card")) renderCommentaryColumn(col);
    refreshAllHandlesFor(docKey, eltId);
    scheduleAlign();
    return;
  }}
}});

function onHandleClicked(handle) {{
  const docKey = handle.dataset.docKey;
  const eltId = handle.dataset.eltId;
  if (!docKey || !eltId) return;
  // Find the local commentary column for this section.
  const sectionId = eltId.includes("/") ? eltId.substring(0, eltId.indexOf("/")) : eltId;
  const localCol = document.querySelector(
    '.section-row[data-section-id="' + cssEscape(sectionId) + '"] .commentary-col[data-col-kind="local"]'
  );
  if (!localCol) return;
  // If this elt already has a local comment, focus the last one (no scroll).
  const existing = localCol.querySelectorAll('.comment-card[data-elt-id="' + cssEscape(eltId) + '"]');
  if (existing.length > 0) {{
    const last = existing[existing.length - 1];
    const ta = last.querySelector("textarea");
    if (ta) ta.focus({{ preventScroll: true }});
    return;
  }}
  // Otherwise: create a fresh empty comment and focus it without scrolling.
  const c = addComment(docKey, eltId, "");
  const card = renderCommentCard({{ docKey, eltId, comment: c, readonly: false }});
  insertCardSorted(localCol, card);
  refreshAllHandlesFor(docKey, eltId);
  scheduleAlign();
  const ta = card.querySelector("textarea");
  if (ta) ta.focus({{ preventScroll: true }});
}}

function insertCardSorted(col, card) {{
  const eid = card.dataset.eltId;
  const cards = col.querySelectorAll(".comment-card");
  for (const c of cards) {{
    const r = compareEltIds(eid, c.dataset.eltId);
    if (r < 0) {{
      col.insertBefore(card, c);
      return;
    }}
  }}
  col.appendChild(card);
}}

// Blur on empty comment textarea → delete the comment (clean up "open-and-leave" cards).
document.addEventListener("focusout", (e) => {{
  const ta = e.target;
  if (!ta.matches || !ta.matches(".comment-card .cmt-text")) return;
  if (ta.value.trim() !== "") return;
  const card = ta.closest(".comment-card");
  if (!card) return;
  const docKey = card.dataset.docKey;
  const eltId = card.dataset.eltId;
  const cid = card.dataset.commentId;
  deleteComment(docKey, eltId, cid);
  const col = card.closest(".commentary-col");
  card.remove();
  if (col && !col.querySelector(".comment-card")) renderCommentaryColumn(col);
  refreshAllHandlesFor(docKey, eltId);
  scheduleAlign();
}});

// Textarea live editing
document.addEventListener("input", (e) => {{
  const ta = e.target;
  if (!ta.matches(".comment-card .cmt-text")) return;
  const card = ta.closest(".comment-card");
  if (!card) return;
  const docKey = card.dataset.docKey;
  const eltId = card.dataset.eltId;
  const cid = card.dataset.commentId;
  updateCommentText(docKey, eltId, cid, ta.value);
  // Live render preview
  const rendered = card.querySelector(".rendered");
  if (rendered) rendered.innerHTML = renderCommentMarkdown(ta.value);
  const meta = card.querySelector(".meta .save-status");
  if (meta) {{
    meta.textContent = "saved " + new Date().toLocaleTimeString();
    clearTimeout(meta._t);
    meta._t = setTimeout(() => {{ meta.textContent = ""; }}, 2200);
  }}
  scheduleAlign();
}});

// ===== Export / Import =====
document.getElementById("exportBtn").addEventListener("click", () => {{
  const data = {{
    version: 2,
    exportedAt: new Date().toISOString(),
    comments: allCommentsAllDocs(),
  }};
  const blob = new Blob([JSON.stringify(data, null, 2)], {{ type: "application/json" }});
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "webpki-policy-comments-" + new Date().toISOString().substring(0, 10) + ".json";
  a.click();
  URL.revokeObjectURL(url);
}});

document.getElementById("importFileBtn").addEventListener("click", () => {{
  document.getElementById("importInput").click();
}});

document.getElementById("importInput").addEventListener("change", (e) => {{
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (ev) => {{
    try {{
      const obj = JSON.parse(ev.target.result);
      const defaultName = deriveSetName(file.name);
      const name = prompt("Name this comments column:", defaultName);
      if (name === null) {{ e.target.value = ""; return; }}
      addLoadedSet(name.trim() || defaultName, obj, file.name);
    }} catch (err) {{
      alert("Load failed: " + err.message);
    }}
    e.target.value = "";
  }};
  reader.readAsText(file);
}});

document.getElementById("importUrlBtn").addEventListener("click", async () => {{
  const url = prompt("Comments JSON URL (must be CORS-accessible):", "");
  if (!url) return;
  try {{
    const resp = await fetch(url, {{ mode: "cors" }});
    if (!resp.ok) throw new Error("HTTP " + resp.status);
    const obj = await resp.json();
    const defaultName = deriveSetName(url);
    const name = prompt("Name this comments column:", defaultName);
    if (name === null) return;
    addLoadedSet(name.trim() || defaultName, obj, url);
  }} catch (err) {{
    alert("Load failed: " + err.message);
  }}
}});

// ===== Search =====
document.getElementById("search").addEventListener("keydown", (e) => {{
  if (e.key === "Enter") {{
    const q = e.target.value.trim();
    if (!q) return;
    runSearch(q);
  }}
}});

function runSearch(q) {{
  const ql = q.toLowerCase();
  const hits = [];
  for (const docKey of SRC_KEYS) {{
    const md = SRC_DATA[docKey].raw.toLowerCase();
    if (md.indexOf(ql) < 0) continue;
    // Snippet hunting: walk MANIFEST for this doc and find first elements whose snippet matches
    for (const r of MANIFEST) {{
      if (r.doc !== docKey) continue;
      if ((r.snippet || "").toLowerCase().indexOf(ql) >= 0 || (r.title || "").toLowerCase().indexOf(ql) >= 0) {{
        hits.push(r);
        if (hits.length > 200) break;
      }}
    }}
    if (hits.length > 200) break;
  }}
  const main = document.getElementById("content");
  main.innerHTML = "";
  const c = document.createElement("div");
  c.innerHTML = '<h1 class="doc-title">Search: ' + escapeHtml(q) + '</h1>' +
                '<div class="doc-meta">' + hits.length + ' match(es).' + (hits.length >= 200 ? ' (truncated)' : '') + '</div>';
  const list = document.createElement("div");
  list.id = "search-results";
  const re = new RegExp("(" + q.replace(/[.*+?^${{}}()|[\]\\]/g, "\\$&") + ")", "ig");
  for (const r of hits) {{
    const eid = r.section + (r.kind === "section" ? "" : "/" + r.kind + r.ord);
    const snip = (r.snippet || "").replace(re, "<mark>$1</mark>");
    const div = document.createElement("div");
    div.className = "search-hit";
    div.innerHTML =
      '<a href="#' + escapeAttr(r.doc) + '/' + escapeAttr(eid) + '">' +
      escapeHtml(SRC_LABELS[r.doc]) + ' ' + escapeHtml(r.ref) + '</a>' +
      '<span class="ctx">' + escapeHtml(r.title || "") + '</span>' +
      '<div>' + snip + '</div>';
    list.appendChild(div);
  }}
  c.appendChild(list);
  main.appendChild(c);
  document.querySelectorAll(".navbtn").forEach((b) => b.classList.remove("active"));
}}

// ===== Init =====
LOADED_SETS = loadLoadedSetsFromStorage();
applySideCountVars();
renderLoadedSetsBar();
navigateHash();
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Build pipeline
# ---------------------------------------------------------------------------

def build_manifest_entries(parsed, doc_key):
    """Flatten a parsed doc into manifest rows: one row per commentable element + each section itself."""
    rows = []
    # preamble elements (no section heading yet)
    for el in parsed["preamble_elements"]:
        rows.append({
            "ref": f"{doc_key}/{el['id']}",
            "doc": doc_key,
            "section": "_preamble",
            "title": "(preamble)",
            "kind": el["kind"],
            "ord": el["ord"],
            "snippet": el["snippet"],
        })
    for sec in parsed["sections"]:
        # the section itself
        rows.append({
            "ref": f"{doc_key}/{sec['id']}",
            "doc": doc_key,
            "section": sec["id"],
            "title": sec["title"],
            "kind": "section",
            "ord": 0,
            "snippet": sec["title"],
        })
        for el in sec["elements"]:
            rows.append({
                "ref": f"{doc_key}/{el['id']}",
                "doc": doc_key,
                "section": sec["id"],
                "title": sec["title"],
                "kind": el["kind"],
                "ord": el["ord"],
                "snippet": el["snippet"],
            })
    return rows


def main():
    src_data = {}
    manifest = []
    for key, label, path in SRC_DOCS:
        full = os.path.join(ROOT, path)
        with open(full, "r", encoding="utf-8") as f:
            raw = f.read()
        parsed = parse_doc(raw)
        rows = build_manifest_entries(parsed, key)
        manifest.extend(rows)
        # collect id lists for cross-reference validity in JS
        section_ids = [s["id"] for s in parsed["sections"]]
        elt_ids = []
        for s in parsed["sections"]:
            for el in s["elements"]:
                elt_ids.append(el["id"])
        for el in parsed["preamble_elements"]:
            elt_ids.append(el["id"])
        src_data[key] = {
            "label": label,
            "filename": path,
            "raw": raw,
            "title": parsed["title"],
            "section_count": len(parsed["sections"]),
            "elt_count": sum(len(s["elements"]) for s in parsed["sections"]) + len(parsed["preamble_elements"]),
            "section_ids": section_ids,
            "elt_ids": elt_ids,
        }

    src_keys = [k for k, _, _ in SRC_DOCS]
    src_labels = {k: lbl for k, lbl, _ in SRC_DOCS}

    src_data_json = json.dumps(src_data, ensure_ascii=False)
    src_keys_json = json.dumps(src_keys)
    src_labels_json = json.dumps(src_labels)
    manifest_json = json.dumps(manifest, ensure_ascii=False)

    src_nav = "".join(
        f'<button class="navbtn" data-doc="{html.escape(k)}" title="Refs: {html.escape(k)}/&lt;section&gt;">{html.escape(lbl)}</button>'
        for k, lbl, _ in SRC_DOCS
    )

    marked_js = load_marked_js()

    rendered = HTML_TEMPLATE.format(
        marked_js=marked_js,
        src_data_json=src_data_json,
        src_keys_json=src_keys_json,
        src_labels_json=src_labels_json,
        manifest_json=manifest_json,
        src_nav=src_nav,
    )

    out_html = os.path.join(ROOT, "index.html")
    with open(out_html, "w", encoding="utf-8") as f:
        f.write(rendered)

    out_manifest = os.path.join(ROOT, "id-manifest.json")
    with open(out_manifest, "w", encoding="utf-8") as f:
        json.dump({"version": 1, "entries": manifest}, f, ensure_ascii=False, indent=2)

    sys.stderr.write(
        f"Wrote {out_html} ({os.path.getsize(out_html):,} bytes), "
        f"{out_manifest} ({len(manifest)} refs across {len(SRC_DOCS)} docs)\n"
    )


if __name__ == "__main__":
    main()

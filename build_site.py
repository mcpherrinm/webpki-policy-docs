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
  - Per-requirement notes persisted in browser localStorage (always-visible side column).
  - Per-requirement review status: unset / reviewed / needs info / noncompliant.
  - Filter bar with status counts; click counts to show/hide requirements in that state.
  - Import/Export notes + statuses as JSON.

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

ANALYSIS_DOCS = [
    ("ambiguity-report", "Ambiguity Report", "ambiguity-report.md"),
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
        for seg in inner.split(";"):
            seg = seg.strip()
            for src, key in CITATION_SRC_TO_KEY.items():
                if seg.startswith(src + " ") or seg == src or seg.startswith(src + " §"):
                    rest = seg[len(src):].strip()
                    pm = re.search(r"\(([^)]+)\)", rest)
                    paren = pm.group(1) if pm else ""
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
    section_stack = []
    section_anchors = []
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
    for it in out:
        it["item_id"] = f"{it['section_anchor']}.{it['item']}"
    return out


def parse_analysis_doc(path):
    """Parse an analysis markdown doc (e.g., the ambiguity report) into structured findings.

    Structure:
      # Title (one H1)
      preamble markdown (between H1 and first H2)
      ## Section heading
        section intro markdown (before first H3)
        ### A1. Finding heading
          body markdown for finding A1
        ### A2. ...

    Findings are identified by an H3 whose text starts with an ID like "A1" / "B12" / "S3".
    """
    text = open(path).read()
    title = None
    preamble_lines = []
    sections = []
    cur_section = None
    cur_finding = None
    state = "pre-h1"

    def finalize_finding():
        nonlocal cur_finding
        if cur_finding is not None and cur_section is not None:
            cur_finding["body"] = "".join(cur_finding.pop("body_lines")).strip("\n")
            cur_section["findings"].append(cur_finding)
            cur_finding = None

    def finalize_section():
        nonlocal cur_section
        finalize_finding()
        if cur_section is not None:
            cur_section["intro"] = "".join(cur_section.pop("intro_lines")).strip("\n")
            sections.append(cur_section)
            cur_section = None

    for line in text.splitlines(keepends=True):
        m_h1 = re.match(r"^# (.+?)\s*$", line)
        m_h2 = re.match(r"^## (.+?)\s*$", line)
        m_h3 = re.match(r"^### (.+?)\s*$", line)

        if m_h1 and state == "pre-h1":
            title = m_h1.group(1)
            state = "preamble"
            continue
        if m_h2:
            finalize_section()
            cur_section = {
                "heading": m_h2.group(1),
                "anchor": "sec-" + slugify(m_h2.group(1), 60),
                "intro_lines": [],
                "findings": [],
            }
            state = "in-section"
            continue
        if m_h3 and state == "in-section":
            finalize_finding()
            heading = m_h3.group(1)
            id_match = re.match(r"^([A-Z]+\d+)\b", heading)
            fid = id_match.group(1) if id_match else slugify(heading, 12)
            # Strip the leading "A1. " from the visible heading text
            short_heading = re.sub(r"^[A-Z]+\d+\.\s*", "", heading).strip()
            cur_finding = {
                "id": fid,
                "heading": short_heading,
                "raw_heading": heading,
                "body_lines": [],
            }
            continue

        if state == "pre-h1":
            continue
        if state == "preamble":
            preamble_lines.append(line)
        elif state == "in-section":
            if cur_finding is not None:
                cur_finding["body_lines"].append(line)
            else:
                cur_section["intro_lines"].append(line)

    finalize_section()

    finding_count = sum(len(s["findings"]) for s in sections)
    return {
        "title": title,
        "preamble": "".join(preamble_lines).strip("\n"),
        "sections": sections,
        "finding_count": finding_count,
    }


def build_reverse_index(req_docs):
    """Build map: 'doc_key#sec-X-Y-Z' → list of '<req_doc_key>::<item_id>' that cite that source section."""
    reverse = {}
    for req_doc_key, doc in req_docs.items():
        for it in doc["items"]:
            for c in it["citations"]:
                if c["sec"]:
                    anchor = "sec-" + c["sec"].replace(".", "-")
                    key = f"{c['doc']}#{anchor}"
                else:
                    key = f"{c['doc']}#top"
                target = f"{req_doc_key}::{it['item_id']}"
                reverse.setdefault(key, []).append(target)
    return reverse


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
    --ok: #2e7d32;
    --ok-bg: #e6f3e6;
    --info: #c08400;
    --info-bg: #fff0c8;
    --bad: #c62828;
    --bad-bg: #fbe4e4;
    --unset: #888;
    --unset-bg: #ececec;
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
    max-width: 1280px;
    margin: 0 auto;
  }}
  /* Requirement view */
  .req-page h1 {{ font-size: 22px; margin-top: 8px; }}
  .req-page .doc-intro {{
    color: var(--muted);
    font-size: 13px;
    margin-bottom: 12px;
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
  /* Status filter bar (sticky-ish under header) */
  .status-filter {{
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    align-items: center;
    margin: 8px 0 18px 0;
    padding: 8px 12px;
    background: var(--bg-alt);
    border: 1px solid var(--border);
    border-radius: 6px;
    font-size: 12.5px;
  }}
  .status-filter .label {{
    color: var(--muted);
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    font-size: 11px;
  }}
  .filter-chip {{
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 3px 10px;
    border-radius: 14px;
    border: 1px solid var(--border);
    background: white;
    cursor: pointer;
    font-size: 12px;
    user-select: none;
  }}
  .filter-chip:hover {{ filter: brightness(0.96); }}
  .filter-chip.inactive {{
    opacity: 0.4;
    text-decoration: line-through;
    background: #f6f6f6;
  }}
  .filter-chip .swatch {{
    width: 9px;
    height: 9px;
    border-radius: 50%;
    display: inline-block;
    background: #888;
    flex: none;
  }}
  .filter-chip.reviewed .swatch {{ background: var(--ok); }}
  .filter-chip.needs-info .swatch {{ background: var(--info); }}
  .filter-chip.noncompliant .swatch {{ background: var(--bad); }}
  .filter-chip.unset .swatch {{ background: var(--unset); }}
  .filter-chip .count {{
    font-weight: 600;
    background: rgba(0,0,0,0.06);
    border-radius: 9px;
    padding: 0 6px;
    font-size: 11px;
    min-width: 18px;
    text-align: center;
  }}
  .filter-toolbtn {{
    margin-left: auto;
    background: white;
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 3px 9px;
    font-size: 11px;
    cursor: pointer;
    color: var(--muted);
  }}
  .filter-toolbtn:hover {{ background: var(--accent-bg); color: var(--fg); }}

  /* Requirement card: two-column grid (requirement | notes) */
  .req-card {{
    background: white;
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 12px 14px;
    margin-bottom: 10px;
    display: grid;
    grid-template-columns: minmax(0, 1fr) 320px;
    gap: 18px;
    border-left-width: 4px;
  }}
  .req-card.status-unset {{ border-left-color: var(--unset); }}
  .req-card.status-reviewed {{ border-left-color: var(--ok); }}
  .req-card.status-needs-info {{ border-left-color: var(--info); }}
  .req-card.status-noncompliant {{ border-left-color: var(--bad); }}
  .req-card.active {{
    box-shadow: 0 0 0 2px var(--accent-bg);
  }}
  .req-card.hidden {{ display: none; }}
  .req-main {{ min-width: 0; }}
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

  /* Status buttons under each requirement */
  .req-status-row {{
    display: flex;
    gap: 4px;
    margin-top: 6px;
    flex-wrap: wrap;
  }}
  .status-btn {{
    border: 1px solid var(--border);
    background: white;
    color: var(--fg);
    padding: 3px 10px;
    border-radius: 12px;
    font-size: 11px;
    cursor: pointer;
    font-family: inherit;
    user-select: none;
  }}
  .status-btn:hover {{ background: var(--accent-bg); }}
  .status-btn.active.unset {{ background: var(--unset-bg); border-color: var(--unset); color: #555; }}
  .status-btn.active.reviewed {{ background: var(--ok); color: white; border-color: var(--ok); }}
  .status-btn.active.needs-info {{ background: var(--info); color: white; border-color: var(--info); }}
  .status-btn.active.noncompliant {{ background: var(--bad); color: white; border-color: var(--bad); }}

  /* Notes column */
  .req-side {{
    border-left: 1px solid var(--border);
    padding-left: 14px;
    display: flex;
    flex-direction: column;
    min-width: 0;
  }}
  .req-side .notes-label {{
    font-size: 10px;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.04em;
    margin-bottom: 4px;
  }}
  .req-side textarea {{
    width: 100%;
    flex: 1;
    min-height: 90px;
    border: 1px solid var(--note-border);
    background: var(--note-bg);
    border-radius: 4px;
    padding: 6px 8px;
    font: inherit;
    font-size: 13px;
    resize: vertical;
    outline: none;
  }}
  .req-side textarea:focus {{ border-color: var(--accent); }}
  .req-side .meta {{
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

  /* Analysis (ambiguity report) styling */
  .analysis-page h1 {{ font-size: 22px; margin-top: 8px; }}
  .analysis-section {{
    text-transform: none !important;
    letter-spacing: 0 !important;
    font-size: 18px !important;
    color: var(--fg) !important;
    margin-top: 32px !important;
    padding-bottom: 6px;
  }}
  .analysis-preamble, .analysis-section-intro {{
    font-size: 13.5px;
    margin-bottom: 14px;
  }}
  .analysis-section-intro p:first-child {{ margin-top: 4px; }}
  .finding-card {{
    border-left-color: var(--accent) !important;
  }}
  .finding-heading {{
    font-weight: 600;
    font-size: 14.5px;
    margin-bottom: 6px;
    line-height: 1.35;
  }}
  .finding-id {{
    display: inline-block;
    background: var(--accent);
    color: white;
    font-family: ui-monospace, "SF Mono", Menlo, monospace;
    font-size: 11px;
    font-weight: 600;
    padding: 1px 7px;
    border-radius: 3px;
    margin-right: 8px;
    vertical-align: middle;
    letter-spacing: 0.02em;
  }}
  .finding-body {{ font-size: 13.5px; }}
  .finding-body p {{ margin: 6px 0; }}
  .finding-body ul, .finding-body ol {{ margin: 6px 0; padding-left: 22px; }}
  .finding-body li {{ margin: 2px 0; }}
  .finding-body code {{
    background: var(--code-bg);
    padding: 1px 4px;
    border-radius: 3px;
    font-size: 12px;
  }}
  .report-link {{
    color: var(--link);
    text-decoration: underline;
    text-decoration-style: dotted;
    text-decoration-color: var(--accent);
    text-underline-offset: 2px;
  }}
  .report-link:hover {{
    color: var(--accent);
    background: var(--accent-bg);
    text-decoration-style: solid;
  }}
  .navbtn.analysis {{ font-style: italic; font-weight: 600; }}

  @media (max-width: 900px) {{
    .req-card {{ grid-template-columns: 1fr; }}
    .req-side {{
      border-left: none;
      border-top: 1px solid var(--border);
      padding-left: 0;
      padding-top: 10px;
    }}
  }}
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
    <span class="nav-label" style="margin-left:8px;">Analysis:</span>
    {analysis_nav}
    <div class="controls">
      <input id="search" type="search" placeholder="Search (Enter to run)…">
      <button id="exportBtn" title="Download all notes + statuses as JSON">Export</button>
      <label>
        Import
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
const ANALYSIS_DATA = {analysis_data_json};
const REVERSE  = {reverse_json};
const SRC_LABELS = {{
{src_label_map}
}};
const REQ_LABELS = {{
{req_label_map}
}};
const ANALYSIS_LABELS = {{
{analysis_label_map}
}};

const STATUS_OPTIONS = [
  {{ value: "unset",         label: "Unset" }},
  {{ value: "reviewed",      label: "Reviewed" }},
  {{ value: "needs-info",    label: "Needs info" }},
  {{ value: "noncompliant",  label: "Noncompliant" }}
];

// === marked.js configuration ===
marked.setOptions({{ gfm: true, breaks: false }});

// === Notes + statuses (localStorage) ===
const NOTE_KEY_PREFIX = "webpki-policy-notes::v1::";
const STATUS_KEY_PREFIX = "webpki-policy-status::v1::";

function noteKey(reqDocKey, itemId) {{
  return NOTE_KEY_PREFIX + reqDocKey + "::" + itemId;
}}
function statusKey(reqDocKey, itemId) {{
  return STATUS_KEY_PREFIX + reqDocKey + "::" + itemId;
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

function getStatus(reqDocKey, itemId) {{
  try {{ return localStorage.getItem(statusKey(reqDocKey, itemId)) || "unset"; }}
  catch (e) {{ return "unset"; }}
}}
function setStatusValue(reqDocKey, itemId, value) {{
  try {{
    if (!value || value === "unset") {{
      localStorage.removeItem(statusKey(reqDocKey, itemId));
    }} else {{
      localStorage.setItem(statusKey(reqDocKey, itemId), value);
    }}
  }} catch (e) {{ console.error(e); }}
}}

function allByPrefix(prefix) {{
  const out = {{}};
  for (let i = 0; i < localStorage.length; i++) {{
    const k = localStorage.key(i);
    if (k && k.startsWith(prefix)) {{
      out[k.substring(prefix.length)] = localStorage.getItem(k);
    }}
  }}
  return out;
}}
function allNotes() {{ return allByPrefix(NOTE_KEY_PREFIX); }}
function allStatuses() {{ return allByPrefix(STATUS_KEY_PREFIX); }}

function importExportPayload(obj, mode) {{
  // Accept either a wrapped object with "notes" and "statuses" keys,
  // or a legacy flat map of "docKey::itemId" -> note text.
  let notes = {{}};
  let statuses = {{}};
  if (obj && typeof obj === "object" && !Array.isArray(obj)) {{
    if (obj.notes && typeof obj.notes === "object") notes = obj.notes;
    if (obj.statuses && typeof obj.statuses === "object") statuses = obj.statuses;
    if (!obj.notes && !obj.statuses) {{
      // Treat as legacy flat-notes object
      notes = obj;
    }}
  }}

  if (mode === "replace") {{
    const keys = [];
    for (let i = 0; i < localStorage.length; i++) {{
      const k = localStorage.key(i);
      if (k && (k.startsWith(NOTE_KEY_PREFIX) || k.startsWith(STATUS_KEY_PREFIX))) keys.push(k);
    }}
    keys.forEach((k) => localStorage.removeItem(k));
  }}

  let nCount = 0;
  for (const composite of Object.keys(notes)) {{
    const v = notes[composite];
    if (typeof v !== "string" || v.trim() === "") continue;
    localStorage.setItem(NOTE_KEY_PREFIX + composite, v);
    nCount++;
  }}
  let sCount = 0;
  for (const composite of Object.keys(statuses)) {{
    const v = statuses[composite];
    if (typeof v !== "string" || !v || v === "unset") continue;
    if (!STATUS_OPTIONS.some((o) => o.value === v)) continue;
    localStorage.setItem(STATUS_KEY_PREFIX + composite, v);
    sCount++;
  }}
  return {{ notes: nCount, statuses: sCount }};
}}

// === Filter state (in-memory, per session) ===
const FILTER_STATE = {{}};
function getFilterState(key) {{
  if (!FILTER_STATE[key]) {{
    FILTER_STATE[key] = new Set(STATUS_OPTIONS.map((o) => o.value));
  }}
  return FILTER_STATE[key];
}}

// === Rendering helpers ===

function escapeHtml(s) {{
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}}

function inlineMarkdownToHtml(s) {{
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

function computeStatusCounts(reqDocKey) {{
  const counts = {{}};
  for (const opt of STATUS_OPTIONS) counts[opt.value] = 0;
  for (const it of REQ_DATA[reqDocKey].items) {{
    const s = getStatus(reqDocKey, it.item_id);
    counts[s] = (counts[s] || 0) + 1;
  }}
  return counts;
}}

function renderStatusFilter(reqDocKey) {{
  const counts = computeStatusCounts(reqDocKey);
  const filter = getFilterState(reqDocKey);
  let html = '<div class="status-filter" data-doc="' + escapeHtml(reqDocKey) + '">';
  html += '<span class="label">Status:</span>';
  for (const opt of STATUS_OPTIONS) {{
    const active = filter.has(opt.value);
    html += '<span class="filter-chip ' + opt.value + (active ? '' : ' inactive') + '" data-filter="' + opt.value + '" title="Click to show/hide ' + escapeHtml(opt.label) + ' requirements">' +
            '<span class="swatch"></span>' + escapeHtml(opt.label) +
            ' <span class="count">' + counts[opt.value] + '</span></span>';
  }}
  html += '<button class="filter-toolbtn" data-filter-action="show-all" title="Show all">Show all</button>';
  html += '<button class="filter-toolbtn" data-filter-action="only-unset" title="Show only unset">Only unset</button>';
  html += '</div>';
  return html;
}}

function statusButtonsHtml(currentStatus) {{
  let html = '<div class="req-status-row" role="group" aria-label="Review status">';
  for (const opt of STATUS_OPTIONS) {{
    const active = currentStatus === opt.value;
    html += '<button class="status-btn ' + opt.value + (active ? ' active' : '') + '" data-status-value="' + opt.value + '">' +
            escapeHtml(opt.label) + '</button>';
  }}
  html += '</div>';
  return html;
}}

// === Page renderers ===

function renderRequirementPage(key) {{
  const doc = REQ_DATA[key];
  const container = document.createElement("div");
  container.className = "req-page";
  container.innerHTML = '<h1>' + escapeHtml(doc.label) + ' — Requirements</h1>' +
    '<div class="doc-intro">' + escapeHtml(doc.items.length + " numbered requirements parsed from " + doc.filename + ". Notes + status are saved in your browser.") + '</div>' +
    renderStatusFilter(key);

  const filter = getFilterState(key);

  let lastSection = null;
  for (const it of doc.items) {{
    if (it.section_path !== lastSection) {{
      const h = document.createElement("h2");
      h.className = "section";
      h.textContent = it.section_path;
      container.appendChild(h);
      lastSection = it.section_path;
    }}
    const note = getNote(key, it.item_id);
    const status = getStatus(key, it.item_id);
    const card = document.createElement("div");
    card.className = "req-card status-" + status;
    if (!filter.has(status)) card.classList.add("hidden");
    card.id = reqAnchor(key, it);
    card.dataset.status = status;
    card.dataset.reqDoc = key;
    card.dataset.itemId = it.item_id;

    card.innerHTML =
      '<div class="req-main">' +
        '<div class="num">#' + escapeHtml(it.item_id) + '</div>' +
        '<div class="text">' + inlineMarkdownToHtml(it.text) + '</div>' +
        renderCitations(it.citations) +
        statusButtonsHtml(status) +
      '</div>' +
      '<div class="req-side">' +
        '<div class="notes-label">Notes</div>' +
        '<textarea data-note="' + escapeHtml(it.item_id) + '" placeholder="Notes for this requirement…">' + escapeHtml(note) + '</textarea>' +
        '<div class="meta"><span class="save-status"></span><span style="font-family:monospace;opacity:0.65">' + escapeHtml(key + "::" + it.item_id) + '</span></div>' +
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
    const fullKey = key + "#" + anchor;
    const citingReqs = REVERSE[fullKey];
    if (citingReqs && citingReqs.length > 0) {{
      const badge = document.createElement("span");
      badge.className = "cited-by-badge";
      badge.textContent = "Cited by " + citingReqs.length;
      badge.dataset.fullkey = fullKey;
      h.appendChild(badge);
    }}
    const link = document.createElement("a");
    link.href = "#src/" + key + "/" + anchor;
    link.textContent = text.replace(/Cited by \d+/, "").trim();
    link.dataset.lvl = h.tagName.substring(1);
    toc.appendChild(link);
  }});

  return container;
}}

// === Linkifier for analysis docs ===

const ANALYSIS_SRC_NAMES = [
  {{ name: "CABF BR",   key: "cabf_br" }},
  {{ name: "LE CP/CPS", key: "letsencrypt_cp_cps" }},
  {{ name: "Mozilla",   key: "mozilla" }},
  {{ name: "Chrome",    key: "chrome" }},
  {{ name: "Apple",     key: "apple" }},
  {{ name: "Microsoft", key: "microsoft" }},
  {{ name: "CCADB",     key: "ccadb" }},
  {{ name: "LE",        key: "letsencrypt_cp_cps" }},
];

function buildAnalysisLinkPatterns(analysisKey) {{
  const escName = (s) => s.replace(/[.*+?^${{}}()|[\]\\\/]/g, "\\$&");
  const srcAlt = ANALYSIS_SRC_NAMES.map((p) => escName(p.name)).join("|");
  const srcNameToKey = {{}};
  for (const p of ANALYSIS_SRC_NAMES) srcNameToKey[p.name] = p.key;

  const patterns = [
    // 1. Req-doc item ref: "roots.md §1.6 #3" or "leaves.md §10 #1–#5"
    {{
      re: /\b(roots|intermediates|leaves|cross-certs)\.md\s+§(\d+(?:\.\d+)*)\s+#(\d+)(?:\s*[–\-]\s*#?\d+)?/g,
      build: (m) => {{
        const sec = m[2].replace(/\./g, "-");
        return {{ href: "#req/" + m[1] + "/" + sec + "." + m[3], text: m[0] }};
      }},
    }},
    // 2. Source-name + section: "CABF BR §1.6.1"
    {{
      re: new RegExp("\\b(" + srcAlt + ")\\s+§(\\d+(?:\\.\\d+)*)", "g"),
      build: (m) => {{
        const key = srcNameToKey[m[1]];
        const anchor = "sec-" + m[2].replace(/\./g, "-");
        return {{ href: "#src/" + key + "/" + anchor, text: m[0] }};
      }},
    }},
    // 3. Source file (optionally with line range): "cabf_br.md:281"
    {{
      re: /\b(cabf_br|mozilla|chrome|apple|microsoft|ccadb|letsencrypt_cp_cps)\.md(?::\d+(?:\s*[–\-]\s*\d+)?)?/g,
      build: (m) => ({{ href: "#src/" + m[1], text: m[0] }}),
    }},
    // 4. Req-doc file: "roots.md" (with optional line range, no §...#... — those handled above)
    {{
      re: /\b(roots|intermediates|leaves|cross-certs)\.md(?::\d+(?:\s*[–\-]\s*\d+)?)?/g,
      build: (m) => ({{ href: "#req/" + m[1], text: m[0] }}),
    }},
  ];
  if (analysisKey) {{
    // 5. Cross-finding refs inside the report: "(A1)", "(B12)"
    patterns.push({{
      re: /\(([A-Z]\d+)\)/g,
      build: (m) => ({{ href: "#analysis/" + analysisKey + "/" + m[1], text: m[0] }}),
    }});
  }}
  return patterns;
}}

function linkifyAnalysisRefs(root, analysisKey) {{
  const patterns = buildAnalysisLinkPatterns(analysisKey);
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {{
    acceptNode: (n) => {{
      let p = n.parentNode;
      while (p && p !== root) {{
        if (p.tagName === "A") return NodeFilter.FILTER_REJECT;
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
    if (!text || text.length < 4) continue;
    const matches = [];
    for (let i = 0; i < patterns.length; i++) {{
      const pat = patterns[i];
      const re = new RegExp(pat.re.source, pat.re.flags);
      let m;
      while ((m = re.exec(text)) !== null) {{
        matches.push({{ index: m.index, len: m[0].length, link: pat.build(m), order: i }});
      }}
    }}
    if (matches.length === 0) continue;
    matches.sort((a, b) => a.index - b.index || a.order - b.order);
    const kept = [];
    let lastEnd = -1;
    for (const m of matches) {{
      if (m.index >= lastEnd) {{
        kept.push(m);
        lastEnd = m.index + m.len;
      }}
    }}
    if (kept.length === 0) continue;
    const frag = document.createDocumentFragment();
    let pos = 0;
    for (const m of kept) {{
      if (m.index > pos) frag.appendChild(document.createTextNode(text.substring(pos, m.index)));
      const a = document.createElement("a");
      a.className = "report-link";
      a.href = m.link.href;
      a.textContent = m.link.text;
      frag.appendChild(a);
      pos = m.index + m.len;
    }}
    if (pos < text.length) frag.appendChild(document.createTextNode(text.substring(pos)));
    tn.parentNode.replaceChild(frag, tn);
  }}
}}

function renderAnalysisPage(key) {{
  const doc = ANALYSIS_DATA[key];
  const container = document.createElement("div");
  container.className = "req-page analysis-page";
  const subtitle = (doc.finding_count || 0) + " findings parsed from " + doc.filename +
    ". Notes are saved in your browser. Source and requirement references are clickable.";
  container.innerHTML = '<h1>' + escapeHtml(doc.title || doc.label) + '</h1>' +
    '<div class="doc-intro">' + escapeHtml(subtitle) + '</div>';

  if (doc.preamble) {{
    const pre = document.createElement("div");
    pre.className = "analysis-preamble src-content";
    pre.innerHTML = marked.parse(doc.preamble);
    linkifyAnalysisRefs(pre, key);
    container.appendChild(pre);
  }}

  for (const section of doc.sections) {{
    const h = document.createElement("h2");
    h.className = "section analysis-section";
    h.id = section.anchor;
    h.textContent = section.heading;
    container.appendChild(h);

    if (section.intro) {{
      const intro = document.createElement("div");
      intro.className = "analysis-section-intro src-content";
      intro.innerHTML = marked.parse(section.intro);
      linkifyAnalysisRefs(intro, key);
      container.appendChild(intro);
    }}

    for (const f of section.findings) {{
      const note = getNote(key, f.id);
      const card = document.createElement("div");
      card.className = "req-card finding-card status-unset";
      card.id = f.id;
      card.dataset.reqDoc = key;
      card.dataset.itemId = f.id;
      const bodyHtml = marked.parse(f.body);
      card.innerHTML =
        '<div class="req-main">' +
          '<div class="finding-heading"><span class="finding-id">' + escapeHtml(f.id) + '</span> ' +
            escapeHtml(f.heading) +
          '</div>' +
          '<div class="finding-body src-content"></div>' +
        '</div>' +
        '<div class="req-side">' +
          '<div class="notes-label">Notes</div>' +
          '<textarea data-note="' + escapeHtml(f.id) + '" placeholder="Notes for this finding…">' + escapeHtml(note) + '</textarea>' +
          '<div class="meta"><span class="save-status"></span><span style="font-family:monospace;opacity:0.65">' + escapeHtml(key + "::" + f.id) + '</span></div>' +
        '</div>';
      const bodyDiv = card.querySelector(".finding-body");
      bodyDiv.innerHTML = bodyHtml;
      linkifyAnalysisRefs(bodyDiv, key);
      container.appendChild(card);
    }}
  }}

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
  }} else if (kind === "analysis") {{
    main.appendChild(renderAnalysisPage(doc));
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
  if (parts[0] === "req") {{
    activate("req", parts[1]);
    if (parts[2]) {{
      const itemId = parts.slice(2).join("/");
      setTimeout(() => {{
        const el = document.getElementById("req/" + parts[1] + "/" + itemId);
        if (el) {{
          // If the card is hidden by a filter, temporarily reveal it.
          if (el.classList.contains("hidden")) el.classList.remove("hidden");
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
  }} else if (parts[0] === "analysis") {{
    activate("analysis", parts[1]);
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

  // Status button on a req card
  const statusBtn = e.target.closest(".status-btn");
  if (statusBtn) {{
    const card = statusBtn.closest(".req-card");
    if (!card) return;
    const newValue = statusBtn.dataset.statusValue;
    const reqDoc = card.dataset.reqDoc;
    const itemId = card.dataset.itemId;
    setStatusValue(reqDoc, itemId, newValue);
    card.dataset.status = newValue;
    // Replace status-* class
    for (const opt of STATUS_OPTIONS) card.classList.remove("status-" + opt.value);
    card.classList.add("status-" + newValue);
    // Toggle active state on the buttons within this row
    card.querySelectorAll(".status-btn").forEach((b) => {{
      b.classList.toggle("active", b.dataset.statusValue === newValue);
    }});
    // Refresh counts in the filter bar
    refreshStatusCounts(reqDoc);
    // If new status is filtered out, fade and hide this card
    const filter = getFilterState(reqDoc);
    card.classList.toggle("hidden", !filter.has(newValue));
    return;
  }}

  // Filter chip
  const chip = e.target.closest(".status-filter .filter-chip");
  if (chip) {{
    const filterBar = chip.closest(".status-filter");
    const reqDoc = filterBar.dataset.doc;
    const filter = getFilterState(reqDoc);
    const v = chip.dataset.filter;
    if (filter.has(v)) {{
      filter.delete(v);
      chip.classList.add("inactive");
    }} else {{
      filter.add(v);
      chip.classList.remove("inactive");
    }}
    applyFilterToCards(reqDoc);
    return;
  }}

  // Filter bar tool button
  const toolBtn = e.target.closest(".status-filter .filter-toolbtn");
  if (toolBtn) {{
    const filterBar = toolBtn.closest(".status-filter");
    const reqDoc = filterBar.dataset.doc;
    const filter = getFilterState(reqDoc);
    const action = toolBtn.dataset.filterAction;
    filter.clear();
    if (action === "show-all") {{
      for (const opt of STATUS_OPTIONS) filter.add(opt.value);
    }} else if (action === "only-unset") {{
      filter.add("unset");
    }}
    // Update chip visuals
    filterBar.querySelectorAll(".filter-chip").forEach((c) => {{
      c.classList.toggle("inactive", !filter.has(c.dataset.filter));
    }});
    applyFilterToCards(reqDoc);
    return;
  }}

  // "Cited by" badge
  const badge = e.target.closest(".cited-by-badge");
  if (badge) {{
    const fullKey = badge.dataset.fullkey;
    const reqs = REVERSE[fullKey] || [];
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

function applyFilterToCards(reqDoc) {{
  const filter = getFilterState(reqDoc);
  document.querySelectorAll('.req-card[data-req-doc="' + reqDoc + '"]').forEach((card) => {{
    const s = card.dataset.status || "unset";
    card.classList.toggle("hidden", !filter.has(s));
  }});
}}

function refreshStatusCounts(reqDoc) {{
  const counts = computeStatusCounts(reqDoc);
  document.querySelectorAll('.status-filter[data-doc="' + reqDoc + '"] .filter-chip').forEach((chip) => {{
    const v = chip.dataset.filter;
    const countEl = chip.querySelector(".count");
    if (countEl) countEl.textContent = counts[v] || 0;
  }});
}}

document.addEventListener("input", (e) => {{
  if (e.target.matches("textarea[data-note]")) {{
    const card = e.target.closest(".req-card");
    if (!card) return;
    const reqDoc = card.dataset.reqDoc;
    const itemId = card.dataset.itemId;
    setNote(reqDoc, itemId, e.target.value);
    const meta = card.querySelector(".req-side .save-status");
    if (meta) {{
      meta.textContent = "saved " + new Date().toLocaleTimeString();
      setTimeout(() => {{ if (meta.textContent.startsWith("saved")) meta.textContent = ""; }}, 2500);
    }}
  }}
}});

// === Export / Import ===

document.getElementById("exportBtn").addEventListener("click", () => {{
  const data = {{
    version: 1,
    exportedAt: new Date().toISOString(),
    notes: allNotes(),
    statuses: allStatuses()
  }};
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
      const mode = confirm("OK = MERGE imported notes/statuses with existing.\nCancel = REPLACE all existing notes/statuses.")
        ? "merge" : "replace";
      const r = importExportPayload(obj, mode);
      alert("Imported " + r.notes + " notes and " + r.statuses + " statuses (" + mode + ").");
      navigateHash();
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
    const re = new RegExp("(" + q.replace(/[.*+?^${{}}()|[\]\\]/g, "\\$&") + ")", "ig");
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
    src_label_map = ",\n".join(f'  "{k}": "{lbl}"' for k, lbl, _ in SRC_DOCS)
    req_label_map = ",\n".join(f'  "{k}": "{lbl}"' for k, lbl, _ in REQ_DOCS)
    analysis_label_map = ",\n".join(f'  "{k}": "{lbl}"' for k, lbl, _ in ANALYSIS_DOCS)

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

    analysis_data = {}
    for key, label, path in ANALYSIS_DOCS:
        parsed = parse_analysis_doc(os.path.join(ROOT, path))
        parsed["label"] = label
        parsed["filename"] = path
        analysis_data[key] = parsed

    reverse_index = build_reverse_index(req_data)
    marked_js = load_marked_js()

    src_data_json = json.dumps(src_data, ensure_ascii=False)
    req_data_json = json.dumps(req_data, ensure_ascii=False)
    analysis_data_json = json.dumps(analysis_data, ensure_ascii=False)
    reverse_json = json.dumps(reverse_index, ensure_ascii=False)

    src_nav = "".join(
        f'<button class="navbtn src" data-kind="src" data-doc="{html.escape(k)}">{html.escape(lbl)}</button>'
        for k, lbl, _ in SRC_DOCS
    )
    req_nav = "".join(
        f'<button class="navbtn req" data-kind="req" data-doc="{html.escape(k)}">{html.escape(lbl)}</button>'
        for k, lbl, _ in REQ_DOCS
    )
    analysis_nav = "".join(
        f'<button class="navbtn analysis" data-kind="analysis" data-doc="{html.escape(k)}">{html.escape(lbl)}</button>'
        for k, lbl, _ in ANALYSIS_DOCS
    )

    rendered = HTML_TEMPLATE.format(
        marked_js=marked_js,
        src_data_json=src_data_json,
        req_data_json=req_data_json,
        analysis_data_json=analysis_data_json,
        reverse_json=reverse_json,
        src_nav=src_nav,
        req_nav=req_nav,
        analysis_nav=analysis_nav,
        src_label_map=src_label_map,
        req_label_map=req_label_map,
        analysis_label_map=analysis_label_map,
    )
    out_path = os.path.join(ROOT, "index.html")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(rendered)
    print(f"Wrote {out_path} ({os.path.getsize(out_path):,} bytes)")


if __name__ == "__main__":
    main()

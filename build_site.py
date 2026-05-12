#!/usr/bin/env python3
"""Build id-manifest.json for the WebPKI policy reference site.

The HTML page (index.html) is a static asset that loads this manifest at
runtime and fetches each markdown doc on demand. This script is therefore
only responsible for emitting the manifest:

  {
    "version": 3,
    "docs": [
      {"key", "label", "version", "path", "title", "section_count", "elt_count"},
      ...
    ],
    "entries": [
      {"ref", "doc", "version", "section", "title", "kind", "ord", "snippet"},
      ...
    ]
  }

The element-ID scheme (computed here and re-derived by the in-page JS walker
on the parsed HTML) is:

  - Section ID = numeric prefix of the heading ("7.1.2.10.2"), else a slug.
                 Headings under the same parent that collide get "-2", "-3".
  - Within a section, sequential counters per kind:
      paragraphs   p1, p2, ...
      list items   li1, li2, ...   (flat across nested lists and ordered/unordered)
      table rows   tr1, tr2, ...   (body rows only, header row skipped)
  - A fully-qualified ref is "<doc_key>/<section_id>[/<kind><n>]".
"""

import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))

SRC_DOCS = [
    ("cabf_br",            "CABF BR",   "2.2.6",      "cabf_br/2.2.6.md"),
    ("mozilla",            "Mozilla",   "3.0",        "mozilla/3.0.md"),
    ("chrome",             "Chrome",    "1.8",        "chrome/1.8.md"),
    ("apple",              "Apple",     "2023-08-15", "apple/2023-08-15.md"),
    ("microsoft",          "Microsoft", "1.1",        "microsoft/1.1.md"),
    ("ccadb",              "CCADB",     "2.0",        "ccadb/2.0.md"),
    ("letsencrypt_cp_cps", "LE CP/CPS", "6.1",        "letsencrypt_cp_cps/6.1.md"),
]


# ---------------------------------------------------------------------------
# Markdown structural parser (enumeration only — the browser renders the
# markdown to HTML with marked.js using the same element-order rules, so the
# IDs computed here match the IDs the page assigns).
# ---------------------------------------------------------------------------

_HEADING_NUM_RE = re.compile(r"^(\d+(?:\.\d+)*)\.?(?:\s|$)")
_LIST_ITEM_RE = re.compile(r"^\s*(?:[-*+]|\d+\.)\s+")
_TABLE_SEP_RE = re.compile(r"^\s*\|?\s*:?-+:?(\s*\|\s*:?-+:?)+\s*\|?\s*$")


def slugify(s, maxlen=48):
    s = re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")
    return s[:maxlen] or "section"


def section_id_from_heading(text):
    text = text.strip()
    m = _HEADING_NUM_RE.match(text)
    if m:
        num = m.group(1)
        rest = text[m.end():].strip().lstrip(".").strip()
        return num, rest or num
    return slugify(text), text


def parse_doc(md_text):
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

    in_code = False
    in_para = False
    in_table = False
    in_list = False
    in_blockquote = False
    last_para_idx = None

    lines = md_text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.lstrip()
        leading = len(line) - len(stripped)

        if stripped.startswith("```") or stripped.startswith("~~~"):
            # CommonMark §4.5: a backtick-fence info string MAY NOT contain
            # backticks, so a line like ```code``` is an inline code span on a
            # paragraph line, not a fence opener. (marked.js renders it the
            # same way.) Detect that case and fall through to the paragraph
            # branch instead of toggling in_code.
            if not (stripped[0] == "`" and "`" in stripped[3:]):
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

        if i == 0 and line.strip() == "---":
            j = i + 1
            while j < len(lines) and lines[j].strip() != "---":
                j += 1
            i = j + 1
            continue

        if line.strip() == "":
            in_para = False
            in_table = False
            last_para_idx = None
            i += 1
            continue

        if re.match(r"^\s*([-*_])\s*\1\s*\1\s*$", line):
            in_para = False
            in_table = False
            in_list = False
            in_blockquote = False
            i += 1
            continue

        if stripped.startswith(">"):
            in_blockquote = True
            in_para = False
            in_table = False
            i += 1
            continue
        if in_blockquote and leading == 0:
            in_blockquote = False

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

        if in_list and leading >= 2:
            in_para = False
            last_para_idx = None
            i += 1
            continue

        if in_list and leading < 2:
            in_list = False

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
                in_table = True
                in_para = False
                last_para_idx = None
                i += 2
                continue

        if _TABLE_SEP_RE.match(line):
            in_table = True
            i += 1
            continue

        if in_table:
            in_table = False

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


def build_manifest_entries(parsed, doc_key, version):
    """Flatten a parsed doc into manifest rows: one row per commentable element + each section itself."""
    rows = []
    for el in parsed["preamble_elements"]:
        rows.append({
            "ref": f"{doc_key}/{el['id']}",
            "doc": doc_key,
            "version": version,
            "section": "_preamble",
            "title": "(preamble)",
            "kind": el["kind"],
            "ord": el["ord"],
            "snippet": el["snippet"],
        })
    for sec in parsed["sections"]:
        rows.append({
            "ref": f"{doc_key}/{sec['id']}",
            "doc": doc_key,
            "version": version,
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
                "version": version,
                "section": sec["id"],
                "title": sec["title"],
                "kind": el["kind"],
                "ord": el["ord"],
                "snippet": el["snippet"],
            })
    return rows


def main():
    docs = []
    entries = []
    for key, label, version, path in SRC_DOCS:
        full = os.path.join(ROOT, path)
        with open(full, "r", encoding="utf-8") as f:
            raw = f.read()
        parsed = parse_doc(raw)
        rows = build_manifest_entries(parsed, key, version)
        entries.extend(rows)
        docs.append({
            "key": key,
            "label": label,
            "version": version,
            "path": path,
            "title": parsed["title"],
            "section_count": len(parsed["sections"]),
            "elt_count": (sum(len(s["elements"]) for s in parsed["sections"])
                          + len(parsed["preamble_elements"])),
        })

    out = os.path.join(ROOT, "id-manifest.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump({"version": 3, "docs": docs, "entries": entries},
                  f, ensure_ascii=False, indent=2)

    sys.stderr.write(
        f"Wrote {out} ({len(entries)} refs across {len(docs)} docs)\n"
    )


if __name__ == "__main__":
    main()

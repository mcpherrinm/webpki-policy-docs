#!/usr/bin/env python3
"""
Build a Boulder compliance review JSON for the WebPKI Policy Reference viewer.

Workflow:
  1. Loads id-manifest.json (doc registry + ref/element list).
  2. Initializes every element to status "na" with a default note.
  3. Layers per-doc overrides defined in review_overrides/*.py.
     Each override module exports OVERRIDES = {<doc_key>: {<eltId>: {status, text}}}.
  4. Section-level dedup: where every child of a section ends up with the
     same (status, text), collapse them to a single comment on the section
     header.
  5. Writes review_boulder.json in v3 import shape.

Run:
  python3 build_review.py
"""
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MANIFEST = json.loads((ROOT / "id-manifest.json").read_text())
OUT = ROOT / "reviews" / "claude_boulder_review.json"
OVERRIDES_DIR = ROOT / "review_overrides"

DEFAULT_NA_TEXT = "Not a technical requirement verifiable against Boulder source code (policy/audit/governance/narrative)."


def now_iso():
    return "2026-05-12T00:00:00.000Z"


def make_comment(cid_suffix, text, status):
    return {
        "id": f"c-rev-{cid_suffix}",
        "text": text,
        "createdAt": now_iso(),
        "updatedAt": now_iso(),
        "status": status,
    }


def main():
    docs = MANIFEST["docs"]
    doc_versions = {d["key"]: d["version"] for d in docs}
    doc_keys = [d["key"] for d in docs]

    # Build skeleton: every entry "na" by default.
    comments = {k: {} for k in doc_keys}
    counter = 0
    for e in MANIFEST["entries"]:
        doc = e["doc"]
        ref = e["ref"]
        if "/" in ref:
            eid = ref.split("/", 1)[1]
        else:
            eid = ref
        comments[doc][eid] = [make_comment(f"{counter}", DEFAULT_NA_TEXT, "na")]
        counter += 1

    # Apply per-doc overrides.
    overrides_total = 0
    sys.path.insert(0, str(OVERRIDES_DIR))
    if OVERRIDES_DIR.exists():
        for f in sorted(OVERRIDES_DIR.glob("*.py")):
            if f.name.startswith("_"):
                continue
            mod_name = f.stem
            mod = __import__(mod_name)
            ov = getattr(mod, "OVERRIDES", {})
            for doc_key, by_elt in ov.items():
                if doc_key not in comments:
                    print(f"WARN: override doc {doc_key} not in manifest", file=sys.stderr)
                    continue
                for eid, entry in by_elt.items():
                    if eid not in comments[doc_key]:
                        print(f"WARN: override {doc_key}::{eid} not in manifest", file=sys.stderr)
                        continue
                    text = entry["text"]
                    status = entry.get("status", "compliant")
                    cid = f"ov-{doc_key}-{eid.replace('/', '_').replace('.', '-')}"
                    comments[doc_key][eid] = [make_comment(cid, text, status)]
                    overrides_total += 1
            print(f"Loaded {f.name}: {sum(len(v) for v in ov.values())} entries")

    # Section-level dedup. When every child of a section ends up with the
    # same (status, text) we collapse the children. Three safe cases:
    #   (a) section header matches the shared child text → just drop
    #       children (section keeps its existing comment).
    #   (b) section header is the default na placeholder → promote the
    #       children's shared comment up to the section header and drop
    #       children.
    #   (c) children are all the default na placeholder while the section
    #       header has a different (more informative) comment → drop the
    #       noisy placeholder children and keep the section header as-is.
    # Anything else (section + children both non-default but different)
    # is left alone, since both are intentional.
    DEFAULT_TUPLE = ("na", DEFAULT_NA_TEXT)
    dedup_removed = 0
    for doc_key, by_elt in comments.items():
        # Group every <sec>/<...> elt under its containing section.
        section_children = {}
        for eid in list(by_elt.keys()):
            if "/" not in eid:
                continue
            sec = eid.split("/", 1)[0]
            section_children.setdefault(sec, []).append(eid)

        for sec_id, child_ids in section_children.items():
            if not child_ids:
                continue
            child_comments = [by_elt[c][0] for c in child_ids]
            first = (child_comments[0]["status"], child_comments[0]["text"])
            if not all((c["status"], c["text"]) == first for c in child_comments):
                continue
            sec_list = by_elt.get(sec_id)
            if not sec_list:
                continue
            sec_comment = sec_list[0]
            sec_tuple = (sec_comment["status"], sec_comment["text"])

            if sec_tuple == first:
                new_sec_tuple = first
            elif sec_tuple == DEFAULT_TUPLE and first != DEFAULT_TUPLE:
                new_sec_tuple = first
            elif first == DEFAULT_TUPLE and sec_tuple != DEFAULT_TUPLE:
                new_sec_tuple = sec_tuple
            else:
                continue

            sec_comment["status"], sec_comment["text"] = new_sec_tuple
            for c in child_ids:
                del by_elt[c]
                dedup_removed += 1

    payload = {
        "version": 3,
        "doc_versions": doc_versions,
        "comments": comments,
    }
    OUT.write_text(json.dumps(payload, indent=2))
    total_entries = sum(len(v) for v in comments.values())
    print(
        f"Wrote {OUT} ({total_entries} entries after dedup, "
        f"{overrides_total} overrides, {dedup_removed} entries collapsed)"
    )


if __name__ == "__main__":
    main()

"""inbox-injection-sanitizer: strip and surface hidden machine-readable
instructions in emails BEFORE AI summarizers/inbox-triage agents see them.

Hook (2026-10-07): Barracuda documented live phishing pairing a normal
human lure with hidden instructions targeting AI email summarizers,
pushing fake vendor payment changes (Barracuda Threat Spotlight).

Deterministic strip-and-surface, not a classifier. Detects:
- HTML comments (<!-- ... -->)
- zero-width / invisible Unicode characters
- base64 blobs that decode to instruction-like text
- CSS-hidden text (display:none, visibility:hidden, font-size:0,
  transparent/color-matching text)
- visually tiny text (font-size <= 1px)
"""

import base64
import re

VERSION = "1.0.0"

ZERO_WIDTH = re.compile(r"[\u200b\u200c\u200d\ufeff\u2060\u180e]")
HTML_COMMENTS = re.compile(r"<!--(.*?)-->", re.S)
BASE64_BLOB = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")
HIDDEN_CSS = re.compile(
    r"<[^>]+style\s*=\s*[\"'][^\"']*?(display\s*:\s*none|visibility\s*:\s*hidden|"
    r"font-size\s*:\s*0(?:px)?|opacity\s*:\s*0|color\s*:\s*transparent)[^\"']*?[\"'][^>]*>",
    re.I)
TINY_FONT = re.compile(r"<[^>]+font-size\s*:\s*([0-9.]+)\s*px", re.I)
STRIP_TAGS = re.compile(r"<[^>]+>")

INSTRUCTION_HINTS = (
    "ignore", "disregard", "instruction", "system prompt", "you are",
    "transfer", "payment", "wire", "bank", "credentials", "password",
)


def _looks_instructional(text):
    tl = text.lower()
    return sum(1 for h in INSTRUCTION_HINTS if h in tl) >= 2


def find_html_comments(text):
    return [{"kind": "html-comment", "content": m.group(1).strip()[:500],
             "instructional": _looks_instructional(m.group(1))}
            for m in HTML_COMMENTS.finditer(text)
            if m.group(1).strip()]


def find_zero_width(text):
    chars = ZERO_WIDTH.findall(text)
    if not chars:
        return []
    return [{"kind": "zero-width-chars", "count": len(chars),
             "content": "N zero-width/invisible characters embedded in text"
                        .replace("N", str(len(chars))),
             "instructional": False}]


def find_base64_blobs(text):
    out = []
    for m in BASE64_BLOB.finditer(text):
        blob = m.group(0)
        try:
            decoded = base64.b64decode(blob).decode("utf-8", "replace")
        except Exception:
            continue
        if len(decoded.strip()) < 10:
            continue
        out.append({"kind": "base64-blob",
                    "content": decoded.strip()[:500],
                    "instructional": _looks_instructional(decoded)})
    return out


def find_hidden_css(text):
    out = []
    for m in HIDDEN_CSS.finditer(text):
        snippet = m.group(0)[:200]
        out.append({"kind": "css-hidden-text", "content": snippet,
                    "instructional": True})
    for m in TINY_FONT.finditer(text):
        try:
            size = float(m.group(1))
        except ValueError:
            continue
        if size <= 1.0:
            out.append({"kind": "tiny-font-text",
                        "content": m.group(0)[:200],
                        "instructional": True})
    return out


def sanitize(text):
    """Return (clean_text, findings). clean_text has hidden content
    removed; findings list every surfaced item."""
    findings = []
    findings.extend(find_html_comments(text))
    findings.extend(find_zero_width(text))
    findings.extend(find_base64_blobs(text))
    findings.extend(find_hidden_css(text))

    clean = HTML_COMMENTS.sub("", text)
    clean = ZERO_WIDTH.sub("", clean)
    clean = HIDDEN_CSS.sub("", clean)
    # drop base64 blobs that decode to instructional text
    def _blob_repl(m):
        blob = m.group(0)
        try:
            decoded = base64.b64decode(blob).decode("utf-8", "replace")
        except Exception:
            return blob
        return "" if _looks_instructional(decoded) else blob
    clean = BASE64_BLOB.sub(_blob_repl, clean)
    clean = STRIP_TAGS.sub(" ", clean)
    clean = re.sub(r"\s+", " ", clean).strip()
    return clean, findings


def report(text):
    clean, findings = sanitize(text)
    return {
        "findings": findings,
        "hidden_instruction_count": sum(1 for f in findings
                                        if f.get("instructional")),
        "clean_text": clean,
        "verdict": ("CLEAN — no hidden machine-readable content detected"
                    if not findings
                    else "%d hidden item(s), %d look(s) instructional"
                    % (len(findings),
                       sum(1 for f in findings if f.get("instructional")))),
    }


def main(argv=None):
    import argparse
    import json
    import sys
    ap = argparse.ArgumentParser(
        description="Strip and surface hidden instructions in email text "
                    "before AI summarizers see them.")
    ap.add_argument("file", nargs="?", help="email text file (default: stdin)")
    args = ap.parse_args(argv)
    text = (open(args.file, encoding="utf-8", errors="replace").read()
            if args.file else sys.stdin.read())
    print(json.dumps(report(text), indent=2))


if __name__ == "__main__":
    main()

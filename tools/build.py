#!/usr/bin/env python3
"""Build the InfoSec advisory site from Markdown files.

Standard library only: nothing is downloaded at build time, and the output
pages contain no JavaScript, no external fonts, no CDN links and no API calls.

Usage:  python3 tools/build.py <advisories_dir> <output_dir>

Each advisory is a Markdown file that starts with a header block:

    ---
    id: CVE-2026-114938
    name: Java4Shell
    severity: Critical
    status: Identify
    published: 2026-11-18
    updated: 2026-11-20
    summary: One sentence shown on the index page.
    ---

Supported Markdown (kept small on purpose): # to #### headings, paragraphs,
- bullets, 1. numbered lists, | tables |, ``` code blocks ```, **bold**, *italic*,
`inline code`, [text](https://link) and --- horizontal rules.
Inside a table cell, write a literal pipe as \\|.
All text is HTML-escaped, so raw HTML in an advisory is shown as text.
"""
import html
import pathlib
import re
import shutil
import sys

REQUIRED = ["id", "name", "severity", "status", "published", "updated", "summary"]
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
ALLOWED_LINK = re.compile(r"^(https://|\./|\.\./|#)")

CSP = ("default-src 'none'; style-src 'self'; img-src 'self'; "
       "base-uri 'none'; form-action 'none'")


def inline(text):
    """Escape text, then apply code, bold, italic and safe links.

    Code spans are handled first and left untouched, so characters such as *
    inside `commands` are never turned into formatting.
    """
    parts = re.split(r"(`[^`]+`)", text)
    out = []
    for part in parts:
        if part.startswith("`") and part.endswith("`") and len(part) > 1:
            out.append("<code>%s</code>" % html.escape(part[1:-1], quote=True))
            continue
        seg = html.escape(part, quote=True)
        seg = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", seg)
        seg = re.sub(r"(?<![*\w])\*([^*\s][^*]*?)\*(?![*\w])", r"<em>\1</em>", seg)

        def link(m):
            label, url = m.group(1), html.unescape(m.group(2))
            if not ALLOWED_LINK.match(url):
                return label  # drop javascript:, data:, http: and other schemes
            return '<a href="%s">%s</a>' % (html.escape(url, quote=True), label)

        out.append(re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", link, seg))
    return "".join(out)


def parse_front_matter(text, path):
    if not text.startswith("---\n"):
        sys.exit("%s: missing --- header block" % path)
    head, _, body = text[4:].partition("\n---\n")
    meta = {}
    for line in head.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            meta[k.strip()] = v.strip()
    missing = [k for k in REQUIRED if not meta.get(k)]
    if missing:
        sys.exit("%s: missing header fields: %s" % (path, ", ".join(missing)))
    if not re.fullmatch(r"CVE-\d{4}-\d{4,7}", meta["id"]):
        sys.exit("%s: id must look like CVE-2026-12345" % path)
    return meta, body


def md_to_html(body):
    lines = body.splitlines()
    out, i = [], 0
    para = []

    def flush_para():
        if para:
            out.append("<p>%s</p>" % inline(" ".join(para)))
            para.clear()

    while i < len(lines):
        line = lines[i]
        s = line.strip()
        if s.startswith("```"):
            flush_para()
            code = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith("```"):
                code.append(lines[i])
                i += 1
            out.append("<pre><code>%s</code></pre>" % html.escape("\n".join(code)))
            i += 1
            continue
        if not s:
            flush_para()
            i += 1
            continue
        m = re.match(r"^(#{1,4})\s+(.*)$", s)
        if m:
            flush_para()
            level = len(m.group(1)) + 1  # page title is h1, so # becomes h2
            anchor = re.sub(r"[^a-z0-9]+", "-", m.group(2).lower()).strip("-")
            out.append('<h%d id="%s">%s</h%d>' % (level, anchor, inline(m.group(2)), level))
            i += 1
            continue
        if s == "---":
            flush_para()
            out.append("<hr>")
            i += 1
            continue
        if s.startswith("|"):
            flush_para()
            rows = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                cells = [c.strip().replace("\\|", "|") for c in
                         re.split(r"(?<!\\)\|", lines[i].strip().strip("|"))]
                if not all(re.fullmatch(r":?-{3,}:?", c) for c in cells):
                    rows.append(cells)
                i += 1
            head, rest = rows[0], rows[1:]
            t = ["<div class=\"table\"><table><thead><tr>"]
            t += ["<th>%s</th>" % inline(c) for c in head]
            t.append("</tr></thead><tbody>")
            for r in rest:
                t.append("<tr>" + "".join("<td>%s</td>" % inline(c) for c in r) + "</tr>")
            t.append("</tbody></table></div>")
            out.append("".join(t))
            continue
        bullet = re.match(r"^[-*]\s+(.*)$", s)
        number = re.match(r"^\d+\.\s+(.*)$", s)
        if bullet or number:
            flush_para()
            tag = "ul" if bullet else "ol"
            pat = r"^[-*]\s+(.*)$" if bullet else r"^\d+\.\s+(.*)$"
            items = []
            while i < len(lines) and re.match(pat, lines[i].strip()):
                items.append(re.match(pat, lines[i].strip()).group(1))
                i += 1
            out.append("<%s>%s</%s>" % (tag, "".join("<li>%s</li>" % inline(x) for x in items), tag))
            continue
        para.append(s)
        i += 1
    flush_para()
    return "\n".join(out)


def page(title, content, depth):
    css = "../" * depth + "assets/style.css"
    home = "../" * depth + "index.html"
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{CSP}">
<meta name="referrer" content="no-referrer">
<meta name="robots" content="noindex, nofollow">
<title>{html.escape(title)}</title>
<link rel="stylesheet" href="{css}">
</head>
<body>
<header><a class="brand" href="{home}">InfoSec Security Advisories</a>
<span class="tag">Internal</span></header>
<main>
{content}
</main>
<footer>Owned by InfoSec. Questions: security@company.com. Classification: Internal.</footer>
</body>
</html>
"""


def badge(kind, value):
    cls = re.sub(r"[^a-z]+", "-", value.lower()).strip("-")
    return '<span class="badge %s-%s">%s</span>' % (kind, cls, html.escape(value))


def build(src, dst):
    src, dst = pathlib.Path(src), pathlib.Path(dst)
    if dst.exists():
        shutil.rmtree(dst)
    (dst / "advisories").mkdir(parents=True)
    shutil.copytree(pathlib.Path(__file__).resolve().parent.parent / "site" / "assets", dst / "assets")

    items = []
    for path in sorted(src.glob("CVE-*.md")):
        meta, body = parse_front_matter(path.read_text(encoding="utf-8"), path)
        fields = "".join(
            "<div><dt>%s</dt><dd>%s</dd></div>" % (k.capitalize(), v)
            for k, v in [("severity", badge("sev", meta["severity"])),
                         ("stage", badge("st", meta["status"])),
                         ("published", html.escape(meta["published"])),
                         ("updated", html.escape(meta["updated"]))])
        content = (f'<p class="back"><a href="../index.html">&larr; All advisories</a></p>'
                   f'<h1>{html.escape(meta["id"])} &ndash; {html.escape(meta["name"])}</h1>'
                   f'<dl class="meta">{fields}</dl>'
                   f'<p class="summary">{inline(meta["summary"])}</p>'
                   f'{md_to_html(body)}')
        (dst / "advisories" / (meta["id"] + ".html")).write_text(
            page(meta["id"] + " " + meta["name"], content, 1), encoding="utf-8")
        items.append(meta)

    items.sort(key=lambda m: (m["updated"]), reverse=True)
    rows = "".join(
        f'<tr><td><a href="advisories/{html.escape(m["id"])}.html">{html.escape(m["id"])}</a></td>'
        f'<td>{html.escape(m["name"])}</td><td>{badge("sev", m["severity"])}</td>'
        f'<td>{badge("st", m["status"])}</td><td>{html.escape(m["published"])}</td>'
        f'<td>{html.escape(m["updated"])}</td><td>{inline(m["summary"])}</td></tr>'
        for m in items)
    index = (
        "<h1>Security advisories</h1>"
        "<p>Company-wide vulnerabilities analysed by InfoSec. Open an advisory for the technical "
        "details, how to check your systems and how to fix them. Report your product line status "
        "on the Confluence Inventory page linked inside each advisory. Status shows the current "
        "response stage: Identify, Prioritize, Remediate, Monitor or Closed.</p>"
        '<div class="table"><table class="index"><thead><tr><th>CVE</th><th>Name</th><th>Severity</th>'
        "<th>Stage</th><th>Published</th><th>Updated</th><th>Summary</th></tr></thead>"
        f"<tbody>{rows}</tbody></table></div>")
    prio = pathlib.Path(__file__).resolve().parent.parent / "site" / "priority.md"
    if prio.exists():
        index += '<section class="priority">' + md_to_html(prio.read_text(encoding="utf-8")) + "</section>"
    (dst / "index.html").write_text(page("Security advisories", index, 0), encoding="utf-8")
    print("Built %d advisories into %s" % (len(items), dst))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    build(sys.argv[1], sys.argv[2])

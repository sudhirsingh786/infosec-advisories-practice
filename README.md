# InfoSec security advisories

Static, read-only advisory pages for company-wide vulnerabilities. InfoSec writes one
Markdown file per CVE; a GitHub Actions workflow turns them into HTML and publishes them
to GitHub Pages. Engineering teams open the index, click a CVE and get the full technical
advisory. Tracking (Identify, Prioritize, Remediate, Monitor) stays in Confluence and ServiceNow.

## Layout

| Path | What it is |
|---|---|
| `advisories/CVE-*.md` | One advisory per CVE (the only files InfoSec edits) |
| `templates/advisory-template.md` | Copy this to start a new advisory |
| `tools/build.py` | Markdown to HTML builder, Python standard library only |
| `site/assets/style.css` | Single local stylesheet |
| `site/priority.md` | Priority and SLA table shown on the front page (keep in line with ServiceNow) |
| `.github/workflows/publish.yml` | Build and deploy on push to `main` |
| `.github/CODEOWNERS` | InfoSec must approve every change |

## Publish a new advisory

1. Create a branch, copy `templates/advisory-template.md` to `advisories/CVE-YYYY-NNNNN.md` and fill it in.
2. Build locally to check it: `python3 tools/build.py advisories _site` then open `_site/index.html`.
3. Open a pull request. A second InfoSec member reviews and approves.
4. Merge. The workflow publishes the site within a few minutes.
5. Put the advisory link in the Confluence response hub and the ServiceNow parent ticket.

To update an advisory, edit the same file, change `updated:` and `status:`, and repeat steps 2 to 4.
Git history is the version history and the pull requests are the approval record.

## Security settings

- Repository visibility: private or internal.
- Settings > Pages: Source = GitHub Actions; Visibility = Private (needs GitHub Enterprise Cloud).
  Without private publishing, do not use GitHub Pages for this content.
- Branch protection on `main`: pull request required, 1 approval from CODEOWNERS, no force push.
- Pin every action in the workflow to a full commit SHA.
- Pages output has no JavaScript and a Content-Security-Policy that blocks scripts,
  external styles, fonts, frames and outbound requests. The builder escapes all text and
  only allows `https://` and relative links.
- Never put customer names, hostnames, IP addresses or exploit code in an advisory.

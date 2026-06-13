"""
Privacy policy page served at GET /privacy (public, no auth).
Required by ChatGPT to publish a GPT that uses this server via Actions.

Contact e-mail can be overridden with PRIVACY_CONTACT_EMAIL.
"""
from __future__ import annotations

import os

_CONTACT = os.getenv("PRIVACY_CONTACT_EMAIL", "privacy@playingwith.info")
_UPDATED = "13 June 2026"

PRIVACY_HTML = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="index, follow">
<title>Privacy Policy — OSINT MCP Server</title>
<style>
  body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
         line-height: 1.6; max-width: 820px; margin: 2rem auto; padding: 0 1rem;
         color: #1a1a1a; background: #fff; }}
  h1 {{ font-size: 1.7rem; }}
  h2 {{ font-size: 1.2rem; margin-top: 2rem; border-bottom: 1px solid #eee; padding-bottom: .25rem; }}
  code {{ background: #f4f4f4; padding: .1rem .3rem; border-radius: 3px; }}
  .updated {{ color: #666; font-size: .9rem; }}
  ul {{ padding-left: 1.3rem; }}
</style>
</head>
<body>
<h1>Privacy Policy — OSINT MCP Server</h1>
<p class="updated">Last updated: {_UPDATED}</p>

<p>This service ("the Service") is an OSINT (Open-Source Intelligence) automation
API intended for <strong>authorized, defensive and educational security work</strong>.
It is consumed by AI assistants (e.g. a custom GPT, Claude or other MCP clients).
This policy explains what data the Service processes and how.</p>

<h2>1. Data we process</h2>
<p>The Service only processes the <strong>indicators you explicitly submit</strong> to run a
workflow, which may include:</p>
<ul>
  <li>Domains, IP addresses, URLs and git repository URLs</li>
  <li>Email addresses, phone numbers and usernames</li>
  <li>Person, company or other entity names</li>
  <li>Vehicle plates / VINs</li>
  <li>Files you upload (images, PDFs, office documents) for metadata or secret analysis</li>
</ul>
<p>We do <strong>not</strong> require account registration and we do not intentionally
collect personal data about you, the operator, beyond what is needed to authenticate
requests (a shared API key) and standard server logs (timestamps, IP, status codes).</p>

<h2>2. How the data is used</h2>
<p>Submitted indicators are used solely to execute the requested OSINT workflow:
running command-line tools inside an isolated sandbox and/or querying third-party
data providers, then returning the aggregated result to the requesting client.</p>

<h2>3. Third-party providers</h2>
<p>To enrich results, indicators you submit may be sent to third-party APIs, each
governed by its own privacy policy. Depending on the workflow these include, among others:
Shodan, VirusTotal, AbuseIPDB, Have I Been Pwned, EmailRep, IPQualityScore, FullContact,
People Data Labs, Intelligence X, Cala.ai and RapidAPI (vehicle data). Only the indicator
needed for that lookup is transmitted. We do not control how these providers process data.</p>

<h2>4. Retention</h2>
<p>Workflow results are stored transiently to allow polling and report generation, and
uploaded files are kept in a temporary directory only for the duration of analysis.
Both are short-lived and are not retained for long-term profiling. Server access logs
follow standard operational rotation.</p>

<h2>5. Data sharing and sale</h2>
<p>We do <strong>not</strong> sell, rent or trade submitted data or results. Data is shared
only with the third-party providers listed above strictly to fulfil a requested lookup.</p>

<h2>6. Your responsibilities (lawful use)</h2>
<p>The Service is provided for lawful, authorized and defensive purposes only. You are
responsible for ensuring you have a legal basis (including under the EU GDPR / Spanish
RGPD where applicable) to query any personal data, and for complying with all applicable
laws. The Service must not be used for doxxing, stalking, harassment, brute-forcing,
active exploitation or any illegal activity.</p>

<h2>7. Security</h2>
<p>Tooling runs in a hardened Docker sandbox (no new privileges, dropped capabilities,
read-only filesystem). All API endpoints require an API key, inputs are validated against
strict allowlists, and PII and secrets are masked in outputs where feasible.</p>

<h2>8. Children</h2>
<p>The Service is not directed to, and must not be used to profile, minors.</p>

<h2>9. Changes</h2>
<p>This policy may be updated; the "Last updated" date above reflects the latest revision.</p>

<h2>10. Contact</h2>
<p>For privacy questions or removal requests, contact:
<a href="mailto:{_CONTACT}">{_CONTACT}</a>.</p>
</body>
</html>"""

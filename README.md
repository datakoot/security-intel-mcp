# Security Intel MCP — by Datakoot

Vulnerability intelligence for AI agents — as MCP tools your agent can call mid-task. One keyless call fuses NVD, CISA KEV and FIRST EPSS. No API keys.

## Tools

| Tool | What it does | Source |
|---|---|---|
| `cve_lookup` | CVE summary: description, CVSS score & severity, CWE, references, plus whether it is actively exploited (CISA KEV) and its exploit probability (EPSS) | NVD (NIST), CISA KEV, FIRST EPSS |
| `known_exploited` | Is a CVE on CISA's Known Exploited Vulnerabilities catalog? Or list the newest exploited CVEs (filter by vendor, product or ransomware use) | CISA KEV |
| `epss_score` | Exploit probability (0–1) and percentile for one or many CVEs: the chance each is exploited in the next 30 days | FIRST EPSS |
| `package_vulnerabilities` | Known vulnerabilities for a package/version | OSV.dev |
| `audit_dependencies` | Audit a whole package.json (or dependency list) in one call | OSV.dev |

No API keys required for any tool.

## Quick start

```
claude mcp add --transport http security-intel https://security.datakoot.com/mcp
```

Or point any MCP client at `https://security.datakoot.com/mcp`.

## Try it in 10 seconds — no key, no signup

Paste this into a terminal:

```bash
curl -s https://security.datakoot.com/mcp \
  -H 'content-type: application/json' \
  -H 'accept: application/json, text/event-stream' \
  -d '{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "cve_lookup", "arguments": {"cve_id": "CVE-2021-44228"}}}'
```

You get Log4Shell (CVE-2021-44228) in one answer: the NVD record (severity, CVSS vector, references), its CISA KEV entry (exploited in the wild, used in ransomware) and its EPSS exploit probability. No API key, nothing to sign up for.

Or point any MCP client at the URL and just ask your agent, in plain language:

- "Is CVE-2021-44228 something I need to worry about?"
- "Which of these CVEs is actually being exploited right now?"
- "Audit my package.json for known vulnerabilities before I deploy."


## Data & attribution

Vulnerability data comes from the [National Vulnerability Database](https://nvd.nist.gov) (NIST — US public domain), CISA's [Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (US public domain), [FIRST EPSS](https://www.first.org/epss/) and [OSV.dev](https://osv.dev) (CC-BY 4.0), the same open sources used by scanners like Trivy and Grype.

Part of [Datakoot](https://datakoot.com) — keyless intelligence APIs for AI agents.

# Security Intel MCP — by Datakoot

Vulnerability intelligence for AI agents — as MCP tools your agent can call mid-task. No API keys.

## Tools

| Tool | What it does | Source |
|---|---|---|
| `cve_lookup` | CVE summary: description, CVSS score & severity, CWE, references | NVD (NIST) |
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

You get the full NVD record for Log4Shell (CVE-2021-44228) — severity, CVSS vector, affected products — no API key, nothing to sign up for.

Or point any MCP client at the URL and just ask your agent, in plain language:

- "Is CVE-2021-44228 something I need to worry about?"
- "Audit my package.json for known vulnerabilities before I deploy."


## Data & attribution

Vulnerability data comes from the [National Vulnerability Database](https://nvd.nist.gov) (NIST — US public domain) and [OSV.dev](https://osv.dev) (CC-BY 4.0), the same open source used by scanners like Trivy and Grype.

Part of [Datakoot](https://datakoot.com) — keyless intelligence APIs for AI agents.

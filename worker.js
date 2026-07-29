/**
 * Security Intel MCP — Datakoot
 * Keyless Model Context Protocol server giving AI agents vulnerability intelligence:
 * CVE lookups, per-package known vulnerabilities, and full dependency-manifest audits.
 *
 * Data sources (all public, keyless, commercial-reuse OK with attribution):
 *   - NVD (NIST)   https://services.nvd.nist.gov   (US government, public domain)
 *   - OSV.dev      https://api.osv.dev              (CC-BY 4.0; used by Trivy, Grype, etc.)
 *
 * (URL-reputation and IP-reputation tools were removed: their upstream providers —
 * abuse.ch/URLhaus and AbuseIPDB — do not permit commercial redistribution of their data.)
 *
 * Cloudflare Worker (module). Bindings: KV namespace "RL" (rate-limit day counter).
 */

const POLAR_ORG = "7f455043-0b15-4a1c-b7a0-9c06c9f3b95e";
const CHECKOUT = "https://buy.polar.sh/polar_cl_Q9y3qLrNbtsssN3w5m8SK56oNcruwrmxLEPnd34oAZf";
const FREE_LIMIT = 100;
const UA = "Datakoot-Security-Intel/1.0 (+https://datakoot.com; contact@datakoot.com)";
const SERVER = { name: "security-intel", version: "2.0.0" };
// OSV ecosystem names (https://ossf.github.io/osv-schema/#affectedpackage-field)
const OSV_ECO = { npm: "npm", pypi: "PyPI", pip: "PyPI", cargo: "crates.io", crates: "crates.io", go: "Go", golang: "Go", maven: "Maven", rubygems: "RubyGems", gem: "RubyGems", nuget: "NuGet", composer: "Packagist", packagist: "Packagist", pub: "Pub", hex: "Hex" };

/* ------------------------------------------------------------------ helpers */
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, Mcp-Session-Id, mcp-protocol-version",
};
const json = (obj, status = 200, extra = {}) =>
  new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json", ...CORS, ...extra } });

async function getJSON(url, { ttl = 3600, method = "GET", body = null } = {}) {
  const opt = { method, headers: { "User-Agent": UA, Accept: "application/json" } };
  if (body) { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body); }
  else { opt.cf = { cacheTtl: ttl, cacheEverything: true }; }
  const r = await fetch(url, opt);
  if (r.status === 404) return { _notfound: true };
  if (!r.ok) return { _error: `upstream ${r.status}` };
  try { return await r.json(); } catch { return { _error: "bad json from upstream" }; }
}
const normEco = (e) => OSV_ECO[String(e || "").toLowerCase().trim()] || null;
const baseVersion = (v) => String(v || "").replace(/^[\^~>=<\s v]+/, "").trim();

/* --------------------------------------------------------------- paywall */
async function checkAccess(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const key = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
  if (key && env.RL) {
    try {
      if (await env.RL.get("pk:" + key)) return { ok: true, pro: true, remaining: null };
      const v = await fetch("https://api.polar.sh/v1/customer-portal/license-keys/validate", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ key, organization_id: POLAR_ORG }),
      });
      if (v.ok) {
        const d = await v.json().catch(() => ({}));
        if (d && (d.status === "granted" || d.valid || d.id)) {
          await env.RL.put("pk:" + key, "1", { expirationTtl: 86400 });
          return { ok: true, pro: true, remaining: null };
        }
      }
    } catch { /* fall through */ }
  }
  if (!env.RL) return { ok: true, pro: false, remaining: null };
  const ip = request.headers.get("CF-Connecting-IP") || "anon";
  const day = new Date().toISOString().slice(0, 10);
  const rk = `rl:${day}:${ip}`;
  const used = parseInt((await env.RL.get(rk)) || "0", 10);
  if (used >= FREE_LIMIT) return { ok: false, pro: false, remaining: 0, reason: "free_limit" };
  await env.RL.put(rk, String(used + 1), { expirationTtl: 90000 });
  return { ok: true, pro: false, remaining: FREE_LIMIT - used - 1 };
}

/* ------------------------------------------------------------- data layer */
function cvssFrom(metrics) {
  if (!metrics) return null;
  const m = (metrics.cvssMetricV31 || metrics.cvssMetricV30 || metrics.cvssMetricV2 || [])[0];
  if (!m || !m.cvssData) return null;
  return { score: m.cvssData.baseScore, severity: m.cvssData.baseSeverity || m.baseSeverity || null, vector: m.cvssData.vectorString, version: m.cvssData.version };
}
async function osvQuery(ecosystem, name, version) {
  const pkg = { name, ecosystem };
  const body = version ? { package: pkg, version } : { package: pkg };
  const d = await getJSON("https://api.osv.dev/v1/query", { method: "POST", body });
  if (d._error) return null;
  return (d.vulns || []).map((v) => ({
    id: v.id, summary: v.summary || (v.details ? v.details.slice(0, 200) : null),
    aliases: v.aliases || [], severity: (v.severity || []).map((s) => s.score),
    published: v.published, references: (v.references || []).slice(0, 3).map((r) => r.url),
  }));
}

/* ------------------------------------------------------------------- tools */
const TOOLS = [
  {
    name: "cve_lookup",
    description: "Look up a CVE by ID and get a compact summary: description, CVSS score & severity, vector, CWE weakness, publish date, and references. Source: NVD (NIST).",
    inputSchema: { type: "object", properties: { cve_id: { type: "string", description: "e.g. CVE-2021-44228" } }, required: ["cve_id"] },
  },
  {
    name: "package_vulnerabilities",
    description: "List known vulnerabilities for a software package (optionally a specific version) via OSV. Ecosystems: npm, pypi, cargo, go, maven, rubygems, nuget, composer, pub, hex.",
    inputSchema: { type: "object", properties: { ecosystem: { type: "string" }, name: { type: "string" }, version: { type: "string", description: "Optional; if given, only vulns affecting that version are returned" } }, required: ["ecosystem", "name"] },
  },
  {
    name: "audit_dependencies",
    description: "Audit a whole dependency manifest for known vulnerabilities in one call. Paste a package.json (as 'manifest'), or pass a 'dependencies' array of {name, version} objects. Returns per-package findings and a summary. Ecosystem defaults to npm.",
    inputSchema: { type: "object", properties: { manifest: { type: "string", description: "Raw package.json contents" }, dependencies: { type: "array", items: { type: "object" }, description: "[{name, version}] entries" }, ecosystem: { type: "string", description: "Default npm" } }, required: [] },
  },
];

async function runTool(name, args) {
  if (name === "cve_lookup") {
    const id = String(args.cve_id || "").toUpperCase().trim();
    if (!/^CVE-\d{4}-\d{4,}$/.test(id)) return { error: "Provide a valid CVE id, e.g. CVE-2021-44228." };
    const d = await getJSON(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${id}`);
    if (d._error || d._notfound || !d.vulnerabilities || !d.vulnerabilities.length) return { error: `CVE '${id}' not found in NVD.` };
    const c = d.vulnerabilities[0].cve;
    const desc = (c.descriptions || []).find((x) => x.lang === "en");
    return {
      id: c.id, status: c.vulnStatus,
      description: desc ? desc.value : null,
      cvss: cvssFrom(c.metrics),
      cwe: (c.weaknesses || []).flatMap((w) => (w.description || []).map((x) => x.value)).filter((v) => v && v !== "NVD-CWE-noinfo").slice(0, 3),
      published: c.published, last_modified: c.lastModified,
      references: (c.references || []).slice(0, 5).map((r) => r.url),
      source: "NVD / NIST (public domain)",
    };
  }
  if (name === "package_vulnerabilities") {
    const eco = normEco(args.ecosystem);
    if (!eco) return { error: "Unsupported ecosystem. Use one of: npm, pypi, cargo, go, maven, rubygems, nuget, composer, pub, hex." };
    const vulns = await osvQuery(eco, args.name, args.version ? baseVersion(args.version) : undefined);
    if (vulns == null) return { error: "vulnerability lookup unavailable" };
    return { ecosystem: eco, name: args.name, version: args.version || null, vulnerability_count: vulns.length, vulnerabilities: vulns, source: "OSV.dev (CC-BY 4.0)" };
  }
  if (name === "audit_dependencies") {
    const eco = normEco(args.ecosystem || "npm") || "npm";
    let deps = [];
    if (args.manifest) {
      let pj; try { pj = JSON.parse(args.manifest); } catch { return { error: "Could not parse 'manifest' as JSON (expected package.json contents)." }; }
      for (const field of ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]) {
        if (pj[field]) for (const [n, v] of Object.entries(pj[field])) deps.push({ name: n, version: baseVersion(v) });
      }
    } else if (Array.isArray(args.dependencies)) {
      deps = args.dependencies.map((d) => ({ name: d.name, version: baseVersion(d.version) })).filter((d) => d.name);
    }
    if (!deps.length) return { error: "Provide a package.json string in 'manifest', or a 'dependencies' array of {name, version}." };
    deps = deps.slice(0, 200);
    const queries = deps.map((d) => (d.version ? { package: { name: d.name, ecosystem: eco }, version: d.version } : { package: { name: d.name, ecosystem: eco } }));
    const res = await getJSON("https://api.osv.dev/v1/querybatch", { method: "POST", body: { queries } });
    if (res._error || !res.results) return { error: "audit unavailable (OSV batch query failed)" };
    const findings = [];
    let totalVulns = 0;
    res.results.forEach((r, i) => {
      const ids = (r.vulns || []).map((v) => v.id);
      if (ids.length) { findings.push({ name: deps[i].name, version: deps[i].version || null, vulnerability_count: ids.length, vulnerability_ids: ids.slice(0, 20) }); totalVulns += ids.length; }
    });
    return {
      ecosystem: eco, packages_audited: deps.length,
      packages_with_vulnerabilities: findings.length, total_vulnerabilities: totalVulns,
      verdict: findings.length === 0 ? "no known vulnerabilities found" : `${findings.length} package(s) have known vulnerabilities — review before shipping`,
      findings, source: "OSV.dev (CC-BY 4.0)",
    };
  }
  return { error: "unknown tool" };
}

/* --------------------------------------------------------------- MCP core */
function rpc(id, result) { return { jsonrpc: "2.0", id, result }; }
function rpcErr(id, code, message) { return { jsonrpc: "2.0", id, error: { code, message } }; }

async function handleMCP(request, env) {
  let body;
  try { body = await request.json(); } catch { return json(rpcErr(null, -32700, "Parse error")); }
  const { id, method, params } = body || {};
  if (method === "initialize") {
    return json(rpc(id, {
      protocolVersion: "2024-11-05", capabilities: { tools: {} }, serverInfo: SERVER,
      instructions: "Security Intel: vulnerability intelligence for AI agents — CVE lookups (NVD), per-package known vulnerabilities and whole-manifest dependency audits (OSV). Call audit_dependencies with a package.json before trusting a project's dependency tree.",
    }));
  }
  if (method === "notifications/initialized" || method === "notifications/cancelled") return new Response(null, { status: 202, headers: CORS });
  if (method === "ping") return json(rpc(id, {}));
  if (method === "tools/list") return json(rpc(id, { tools: TOOLS }));
  if (method === "tools/call") {
    const access = await checkAccess(request, env);
    if (!access.ok) return json(rpc(id, { content: [{ type: "text", text: `Free tier limit reached (${FREE_LIMIT} calls/day). Upgrade to Pro for unlimited access with one key across all Datakoot servers: ${CHECKOUT}` }], isError: true }));
    const tname = params && params.name;
    const args = (params && params.arguments) || {};
    if (!TOOLS.find((t) => t.name === tname)) return json(rpcErr(id, -32602, `Unknown tool: ${tname}`));
    try {
      const out = await runTool(tname, args);
      const meta = access.pro ? "" : `\n\n(${access.remaining} free calls left today)`;
      return json(rpc(id, { content: [{ type: "text", text: JSON.stringify(out, null, 2) + meta }], isError: !!(out && out.error) }));
    } catch (e) {
      return json(rpc(id, { content: [{ type: "text", text: "Error: " + (e && e.message || String(e)) }], isError: true }));
    }
  }
  return json(rpcErr(id, -32601, `Method not found: ${method}`));
}

/* ----------------------------------------------------------------- landing */
const CSS = `:root{--bg:#0b0e14;--panel:#111725;--border:#1e2636;--text:#e6edf3;--muted:#8b98a9;--accent:#4ade80;--accent2:#22d3ee}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:ui-sans-serif,system-ui,-apple-system,sans-serif;line-height:1.6}
a{color:var(--accent2);text-decoration:none}a:hover{text-decoration:underline}
.wrap{max-width:1000px;margin:0 auto;padding:0 20px}
header{position:sticky;top:0;z-index:50;background:#0b0e14;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:18px;padding:12px 20px}
.logo{display:flex;align-items:center;gap:9px;font-weight:800;font-size:19px}.logo svg{display:block}
nav{display:flex;gap:16px;margin-left:auto;flex-wrap:wrap;font-size:14px}nav a{color:var(--muted)}nav a:hover{color:var(--text)}
.hero{padding:64px 0 32px}.hero h1{font-size:44px;line-height:1.1;margin:0 0 14px}.hero .accent{color:var(--accent)}
.sub{font-size:19px;color:var(--muted);max-width:640px}
.section{padding:28px 0;border-top:1px solid var(--border)}
.grid{display:grid;grid-template-columns:1fr;gap:16px}@media(min-width:760px){.grid{grid-template-columns:1fr 1fr}}
.card{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:18px;min-width:0}
.card h3{margin:0 0 6px;font-size:16px}.card code{color:var(--accent);font-size:13px}.card p{margin:6px 0 0;color:var(--muted);font-size:14px}
.cmd{display:flex;align-items:center;gap:8px;background:#0a0d13;border:1px solid var(--border);border-radius:8px;padding:10px 12px;margin:14px 0;overflow-x:auto}
.cmd code{font:13px/1.5 ui-monospace,Menlo,monospace;color:var(--text);white-space:nowrap}
.tiers{display:grid;grid-template-columns:1fr;gap:14px}@media(min-width:760px){.tiers{grid-template-columns:1fr 1fr 1fr}}
.tier{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:18px}.tier b{font-size:18px}.tier span{display:block;color:var(--muted);font-size:14px;margin-top:4px}
.btn{display:inline-block;background:var(--accent);color:#06210f;font-weight:700;padding:10px 18px;border-radius:8px;margin-top:8px}
footer{border-top:1px solid var(--border);padding:32px 20px;color:var(--muted);font-size:14px;text-align:center}`;
const MARK = `<svg width="26" height="26" viewBox="-34 -34 68 68" style="vertical-align:-4px"><g stroke="#4ade80" stroke-width="5" fill="none" stroke-linejoin="round"><polygon points="0,-30 26,-15 26,15 0,30 -26,15 -26,-15"/></g><g fill="#4ade80"><circle cx="0" cy="-12" r="6"/><circle cx="-11" cy="8" r="6"/><circle cx="11" cy="8" r="6"/></g></svg>`;

function landing(host) {
  const ep = `https://${host}/mcp`;
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Intel MCP — Vulnerability intelligence for your AI agent | Datakoot</title>
<meta name="description" content="Keyless MCP server giving AI agents vulnerability intelligence: CVE lookups (NVD), per-package known vulnerabilities and whole dependency-manifest audits (OSV).">
<style>${CSS}</style></head><body>
<header><a href="https://datakoot.com/" style="color:inherit"><div class="logo">${MARK}Data<span style="color:var(--accent)">koot</span></div></a>
<nav><a href="https://datakoot.com/">Datakoot</a><a href="#tools">Tools</a><a href="#start">Quick start</a><a href="#pricing">Pricing</a><a href="https://github.com/datakoot">GitHub</a></nav></header>
<div class="wrap">
<section class="hero"><h1>Know if your agent's dependencies are <span class="accent">vulnerable</span>.</h1>
<p class="sub">Security Intel gives AI agents vulnerability intelligence: look up any CVE, list known vulnerabilities for a package, or audit an entire dependency manifest in one call — from NVD and OSV. No API keys.</p></section>

<section class="section" id="tools"><h2>Tools</h2><div class="grid">
<div class="card"><h3><code>cve_lookup</code></h3><p>CVE summary: CVSS score, severity, CWE, references (NVD).</p></div>
<div class="card"><h3><code>package_vulnerabilities</code></h3><p>Known vulnerabilities for a package/version (OSV).</p></div>
<div class="card"><h3><code>audit_dependencies</code></h3><p>Audit a whole package.json for vulnerabilities in one call.</p></div>
</div></section>

<section class="section" id="start"><h2>Quick start</h2>
<p class="sub">One line, no key. Works with Claude, Cursor, and any MCP client.</p>
<div class="cmd"><code>claude mcp add --transport http security-intel ${ep}</code></div>
<p style="color:var(--muted);font-size:14px">Or point any MCP client at <code>${ep}</code></p></section>

<section class="section" id="pricing"><h2>Pricing</h2><div class="tiers">
<div class="tier"><b>Free</b><span>100 calls / day</span><span>Every tool, no key.</span></div>
<div class="tier"><b>$19/mo · Pro</b><span>Unlimited calls</span><span>1 seat · one key unlocks all Datakoot servers.</span><a class="btn" href="${CHECKOUT}">Upgrade</a></div>
<div class="tier"><b>$49/mo · Team</b><span>Unlimited calls</span><span>Up to 5 seats.</span><a class="btn" href="${CHECKOUT}">Upgrade</a></div>
</div></section>
</div>
<footer><a href="https://datakoot.com/" style="color:inherit">Datakoot</a> — infrastructure for the agent economy · <a href="https://github.com/datakoot">GitHub</a> · Data: NVD/NIST (public domain), OSV.dev (CC-BY 4.0)</footer>
</body></html>`;
}

/* ------------------------------------------------------------------ router */
export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") return new Response(null, { headers: CORS });
    const url = new URL(request.url);
    if (url.pathname === "/mcp" || url.pathname === "/sse") {
      if (request.method === "POST") return handleMCP(request, env);
      return json({ error: "POST JSON-RPC to this endpoint (MCP streamable HTTP)" }, 405);
    }
    if (url.pathname === "/health") return json({ ok: true, server: SERVER });
    if (url.pathname === "/" || url.pathname === "") return new Response(landing(url.host), { headers: { "Content-Type": "text/html; charset=utf-8", ...CORS } });
    return new Response("Not found", { status: 404, headers: CORS });
  },
};

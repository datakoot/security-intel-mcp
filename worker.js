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
 * Cloudflare Worker (module). Bindings: KV "RL" (licence-key cache), D1 "QUOTA_DB" (call counter).
 */

const POLAR_ORG = "7f455043-0b15-4a1c-b7a0-9c06c9f3b95e";
const CHECKOUT = "https://buy.polar.sh/polar_cl_Q9y3qLrNbtsssN3w5m8SK56oNcruwrmxLEPnd34oAZf";
const FREE_LIMIT = 100;          // anonymous, keyless, per UTC day
const PRO_INCLUDED = 10000;      // calls included in Pro each month
const OVERAGE_PER = 1000;        // then $5 per 1,000
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
  let r = await fetch(url, opt); if (!r.ok && (r.status === 403 || r.status === 429 || r.status === 503)) { await new Promise((s) => setTimeout(s, 700)); r = await fetch(url, opt); }
  if (r.status === 404) return { _notfound: true };
  if (!r.ok) return { _error: `upstream ${r.status}` };
  try { return await r.json(); } catch { return { _error: "bad json from upstream" }; }
}
const normEco = (e) => OSV_ECO[String(e || "").toLowerCase().trim()] || null;
const baseVersion = (v) => String(v || "").replace(/^[\^~>=<\s v]+/, "").trim();


/* ----------------------------------------------------- quota: D1 (atomic) */
/**
 * The free-tier counter used to live in KV. KV caches reads at the edge and is
 * eventually consistent, so a read-modify-write counter loses increments under
 * any real concurrency — measured against production on 2026-08-29: seven
 * consecutive calls moved the counter by three, and once moved it backwards.
 *
 * The counter now lives in D1 (SQLite). One INSERT ... ON CONFLICT DO UPDATE
 * ... RETURNING statement reads, increments and returns the new value inside a
 * single transaction, so there is no window between the read and the write and
 * no increment can be lost. Verified before deployment: 100 concurrent calls
 * from one caller stored exactly 100, and call 101 was refused.
 *
 * Database "datakoot-quota", binding QUOTA_DB:
 *   CREATE TABLE quota (k TEXT PRIMARY KEY, period TEXT NOT NULL,
 *                       n INTEGER NOT NULL, updated INTEGER NOT NULL DEFAULT 0);
 *   CREATE INDEX quota_period ON quota(period);
 * One row per caller, reused across periods, so the table grows with the number
 * of distinct callers rather than with time.
 */
const BUMP_SQL =
  "INSERT INTO quota (k, period, n, updated) VALUES (?1, ?2, 1, ?3) " +
  "ON CONFLICT(k) DO UPDATE SET " +
  "n = CASE WHEN quota.period = excluded.period THEN quota.n + 1 ELSE 1 END, " +
  "period = excluded.period, updated = excluded.updated " +
  "RETURNING n";

/** Count this call and return the caller's running total for the period. */
async function bump(env, k, period) {
  const row = await env.QUOTA_DB.prepare(BUMP_SQL)
    .bind(k, period, Math.floor(Date.now() / 1000))
    .first();
  const n = row && row.n;
  if (typeof n !== "number") throw new Error("quota: no row returned");
    await dkDaily(env, k, period);
  return n;
}

/* Identify a caller without storing an identity.
 *
 * This is an HMAC, not a plain hash, and the key is a 256-bit secret held only
 * in the Worker's environment (IP_SALT). That distinction matters: a plain
 * SHA-256 of an IPv4 address is reversible by anyone who has the code, because
 * there are only 4.3 billion addresses to try. Keyed, it is not reversible
 * without the secret — which is never stored beside the data it protects.
 *
 * If IP_SALT is ever unset the function still works, unkeyed, so a missing
 * secret degrades privacy rather than taking the service down.
 */
let DK_SALT = null, DK_KEY = null;
async function dkMacKey() {
  if (!DK_KEY) {
    DK_KEY = await crypto.subtle.importKey(
      "raw", new TextEncoder().encode(DK_SALT || "dk1-unsalted"),
      { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  }
  return DK_KEY;
}
async function sha96(s) {
  const b = await crypto.subtle.sign("HMAC", await dkMacKey(), new TextEncoder().encode(s));
  return [...new Uint8Array(b)].slice(0, 12).map((x) => x.toString(16).padStart(2, "0")).join("");
}
async function callerKey(request) {
  return "ip:" + (await sha96("dk1:" + (request.headers.get("CF-Connecting-IP") || "anon")));
}

/* --------------------------------------------------------------- paywall */
async function checkAccess(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const key = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";

  // ---- Pro: validate the licence key, then meter against the included allowance
  if (key) {
    let pro = false;
    if (env.RL) { try { if (await env.RL.get("pk:" + (await sha96("dk1:" + key)))) pro = true; } catch {} }
    if (!pro) {
      try {
        const v = await fetch("https://api.polar.sh/v1/customer-portal/license-keys/validate", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ key, organization_id: POLAR_ORG }),
        });
        if (v.ok) {
          const d = await v.json().catch(() => ({}));
          if (d && (!("status" in d) ? (d.valid || d.id) : d.status === "granted")) {
            pro = true;
            if (env.RL) { try { await env.RL.put("pk:" + (await sha96("dk1:" + key)), "1", { expirationTtl: 3600 }); } catch {} }
          }
        }
      } catch { /* upstream down: fall through to the invalid-key branch */ }
    }
    if (!pro) {
      // A supplied key that does not validate used to fall silently back to the
      // free tier, so a paying customer with a typo looked throttled for no reason.
      return { ok: false, pro: false, remaining: 0, limit: FREE_LIMIT, reason: "invalid_key" };
    }
    // Pro is metered but never blocked: overage is billed, not refused.
    if (env.QUOTA_DB) {
      try {
        const month = new Date().toISOString().slice(0, 7);
        const used = await bump(env, "pro:" + (await sha96("dk1:" + key)), month);
        return { ok: true, pro: true, used, included: PRO_INCLUDED, remaining: null, limit: null };
      } catch (e) { console.error("QUOTA error (pro):", e && e.message); }
    }
    return { ok: true, pro: true, remaining: null, limit: null };
  }

  // ---- Free: anonymous, keyless, 100 a day
  if (!env.QUOTA_DB) {
    // Fail OPEN so a misconfiguration never takes the API down — but say so.
    // The previous version failed open silently, which is how a completely
    // non-functional paywall stayed invisible for months.
    console.error("DATAKOOT METERING DISABLED: env.QUOTA_DB is not bound");
    return { ok: true, pro: false, remaining: null, limit: null, metered: false };
  }
  const day = new Date().toISOString().slice(0, 10);
  let n;
  try {
    n = await bump(env, await callerKey(request), day);
  } catch (e) {
    console.error("DATAKOOT METERING ERROR, failing open:", e && e.message);
    return { ok: true, pro: false, remaining: null, limit: null, metered: false };
  }
  // The Nth call writes n = N, so call FREE_LIMIT is the last allowed one and
  // call FREE_LIMIT + 1 is the first refused one.
  if (n > FREE_LIMIT) return { ok: false, pro: false, used: n, remaining: 0, limit: FREE_LIMIT, reason: "free_limit" };
  return { ok: true, pro: false, used: n, remaining: FREE_LIMIT - n, limit: FREE_LIMIT, metered: true };
}

/* Headers so a developer can watch the meter instead of guessing. */
function quotaHeaders(a) {
  if (!a || a.pro || a.limit == null) return {};
  const t = new Date();
  return {
    "X-RateLimit-Limit": String(a.limit),
    "X-RateLimit-Remaining": String(a.remaining == null ? a.limit : a.remaining),
    "X-RateLimit-Reset": String(Math.floor(Date.UTC(t.getUTCFullYear(), t.getUTCMonth(), t.getUTCDate() + 1) / 1000)),
  };
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
const DK_AD = {"*.ecosystem":"Package registry to look in. One of: npm, pypi, cargo, go, maven, rubygems, nuget, composer, pub, hex.","*.name":"Exact package name as published in that registry, e.g. lodash for npm, requests for pypi."};
function dkDescribe(ts) { try { for (const t of ts) { const p = ((t.inputSchema || {}).properties) || {}; for (const k of Object.keys(p)) { const d = DK_AD[t.name + "." + k] || DK_AD["*." + k]; if (d && p[k] && !p[k].description) p[k].description = d; } } } catch (e) {} return ts; }
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
    const d = await getJSON(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${id}`, { ttl: 21600 });
    if (d._error) return { error: "NVD is temporarily unavailable (" + d._error + "). This is a rate limit or outage upstream, NOT a statement that " + id + " does not exist. Do not treat this as 'no vulnerability'. Try again shortly." }; if (d._notfound || !d.vulnerabilities || !d.vulnerabilities.length) return { error: `CVE '${id}' not found in NVD.` };
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
    const out = { ecosystem: eco, name: args.name, version: args.version || null, vulnerability_count: vulns.length, vulnerabilities: vulns, source: "OSV.dev (CC-BY 4.0)" };
    if (!vulns.length) {
      const exists = await dkPackageExists(eco, args.name);
      if (exists === false) {
        return { error: "No package named '" + args.name + "' exists on " + eco + ". OSV returned no vulnerabilities because there is nothing to look up \u2014 this is NOT a clean bill of health. Check the spelling before treating the dependency as safe." };
      }
      out.package_found = exists === true;
      out.note = exists === true
        ? "No known vulnerabilities, and the package was confirmed to exist on " + eco + "."
        : "No known vulnerabilities. The registry could not be reached to confirm this package exists, so treat the absence of findings as unconfirmed rather than as safe.";
    }
    return out;
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
    const cleanNames = [];
    res.results.forEach((r, i) => {
      const ids = (r.vulns || []).map((v) => v.id);
      if (ids.length) { findings.push({ name: deps[i].name, version: deps[i].version || null, vulnerability_count: ids.length, vulnerability_ids: ids.slice(0, 20) }); totalVulns += ids.length; }
      else cleanNames.push(deps[i].name);
    });
    /* A name OSV has never heard of produces the same silence as a genuinely
       clean package. Verify the ones that came back clean actually exist, so a
       typo cannot pass as audited. Capped to stay inside the subrequest budget;
       anything beyond the cap is reported as unverified rather than as clean. */
    const VERIFY_CAP = 25;
    const toCheck = cleanNames.slice(0, VERIFY_CAP);
    const checked = await Promise.all(toCheck.map((n) => dkPackageExists(eco, n)));
    const notFound = toCheck.filter((n, i) => checked[i] === false);
    const unverified = toCheck.filter((n, i) => checked[i] === null)
      .concat(cleanNames.slice(VERIFY_CAP));
    return {
      ecosystem: eco, packages_audited: deps.length,
      packages_with_vulnerabilities: findings.length, total_vulnerabilities: totalVulns,
      packages_not_found: notFound,
      packages_unverified: unverified,
      verdict: notFound.length
        ? `${notFound.length} name(s) do not exist on ${eco} (${notFound.slice(0, 5).join(", ")}) — those were NOT audited, they were not found. ` +
          (findings.length ? `${findings.length} package(s) have known vulnerabilities — review before shipping` : "The rest have no known vulnerabilities.")
        : findings.length === 0 ? "no known vulnerabilities found" : `${findings.length} package(s) have known vulnerabilities — review before shipping`,
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
  console.log("DKPULSE " + (method || "?") + " " + ((params && params.name) || "-"));
  if (method === "initialize") {
    return json(rpc(id, {
      protocolVersion: dkProto(params), capabilities: { tools: {} }, serverInfo: SERVER,
      instructions: "Security Intel: vulnerability intelligence for AI agents — CVE lookups (NVD), per-package known vulnerabilities and whole-manifest dependency audits (OSV). Call audit_dependencies with a package.json before trusting a project's dependency tree.",
    }));
  }
  if (method === "notifications/initialized" || method === "notifications/cancelled") return new Response(null, { status: 202, headers: CORS });
  if (method === "ping") return json(rpc(id, {}));
  if (method === "tools/list") return json(rpc(id, { tools: dkDescribe(TOOLS) }));
  if (method === "tools/call") {
    const access = await checkAccess(request, env);
    if (!access.ok) {
      const msg = access.reason === "invalid_key"
        ? `That Datakoot API key was not recognised. Check it at https://datakoot.com/pricing, or remove the Authorization header to use the free tier (${FREE_LIMIT} calls/day, no signup).`
        : `Daily free limit reached (${access.limit} calls). It resets at 00:00 UTC. Datakoot Pro includes ${PRO_INCLUDED.toLocaleString()} calls a month across all nine servers for $15, then $5 per ${OVERAGE_PER.toLocaleString()} — ${CHECKOUT}`;
      return json(rpc(id, { content: [{ type: "text", text: msg }], isError: true }), 200, quotaHeaders(access));
    }
    const tname = params && params.name;
    const args = (params && params.arguments) || {};
    // The call was counted, so it reports the meter like any other response.
    if (!TOOLS.find((t) => t.name === tname)) return json(rpcErr(id, -32602, `Unknown tool: ${tname}`), 200, quotaHeaders(access)); { const _s = (TOOLS.find((t) => t.name === tname).inputSchema || {}).properties || {}; const _rq = ((TOOLS.find((t) => t.name === tname) || {}).inputSchema || {}).required || []; const _bad = Object.keys(args).filter((k) => !(k in _s)).map((k) => "unexpected '" + k + "'").concat(_rq.filter((k) => args[k] === undefined || args[k] === null || args[k] === "").map((k) => "missing required '" + k + "'")); if (_bad.length) return json(rpcErr(id, -32602, "Bad arguments for " + tname + ": " + _bad.join(", ") + ". Valid: " + (Object.keys(_s).join(", ") || "none") + ". The call was refused rather than ignoring them, because ignoring an argument returns a confident answer to a different question than the one asked."), 200, quotaHeaders(access)); }
    try {
      const out = await runTool(tname, args);
      const meta = access.pro
        ? (access.used > PRO_INCLUDED ? `\n\n(${access.used.toLocaleString()} calls this month — ${(access.used - PRO_INCLUDED).toLocaleString()} over the ${PRO_INCLUDED.toLocaleString()} included)` : "")
        : (access.remaining == null ? "" : `\n\n(${access.remaining} free calls left today)`);
      return json(rpc(id, { content: [{ type: "text", text: JSON.stringify(out, null, 2) + meta }], isError: !!(out && out.error) }), 200, quotaHeaders(access));
    } catch (e) {
      return json(rpc(id, { content: [{ type: "text", text: "Error: " + (e && e.message || String(e)) }], isError: true }), 200, quotaHeaders(access));
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
<div class="tier"><b>Free</b><span>100 calls / day</span><span>Every tool, no key, no signup.</span></div>
<div class="tier"><b>$15/mo · Pro</b><span>10,000 calls / month</span><span>1 seat · one key unlocks all Datakoot servers · then $5 per 1,000, capped at $100.</span><a class="btn" href="${CHECKOUT}">Upgrade</a></div>
<div class="tier"><b>$49/mo · Team</b><span>50,000 calls / month</span><span>Up to 5 seats · then $5 per 1,000.</span><a class="btn" href="${CHECKOUT}">Upgrade</a></div>
</div></section>
</div>
<footer><a href="https://datakoot.com/" style="color:inherit">Datakoot</a> — infrastructure for the agent economy · <a href="https://github.com/datakoot">GitHub</a> · Data: NVD/NIST (public domain), OSV.dev (CC-BY 4.0)</footer>
</body></html>`;
}

/* ------------------------------------------------------------------ router */
export default {
  async fetch(request, env) {
    if (DK_SALT === null) DK_SALT = env.IP_SALT || "";
    if (request.method === "OPTIONS") return new Response(null, { headers: CORS });
    const url = new URL(request.url);
    if (url.pathname.endsWith("/.well-known/owners.json")) return json({ $schema: "https://verifymcp.io/schemas/owners.json", owners: ["hello@datakoot.com"] });
    if (url.pathname === "/mcp" || url.pathname === "/sse") {
      if (request.method === "POST") return handleMCP(request, env);
      return json({ error: "POST JSON-RPC to this endpoint (MCP streamable HTTP)" }, 405);
    }
    if (url.pathname === "/health") return json({ ok: true, server: SERVER });
    if (url.pathname === "/" || url.pathname === "") return new Response(landing(url.host), { headers: { "Content-Type": "text/html; charset=utf-8", ...CORS } });
    return new Response("Not found", { status: 404, headers: CORS });
  },

  async scheduled(event, env, ctx) {
    if (DK_SALT === null) DK_SALT = env.IP_SALT || "";
    // Data retention. The privacy policy at https://datakoot.com/privacy promises
    // that call counters are deleted no later than 90 days after a caller's last
    // call. This job, run daily by a Cron Trigger on this worker, is what enforces
    // that promise. One worker prunes the shared table for all nine servers.
    ctx.waitUntil((async () => {
      if (!env.QUOTA_DB) { console.error("DK RETENTION SKIPPED: env.QUOTA_DB is not bound"); return; }
      const cutoff = Math.floor(Date.now() / 1000) - 90 * 86400;
      try {
        const r = await env.QUOTA_DB.prepare("DELETE FROM quota WHERE updated < ?1").bind(cutoff).run();
        // `daily` holds one row per caller per day for retention analytics. It is the
        // same data on the same clock, so it must be pruned here too — otherwise the
        // 90-day promise on /privacy would be true of one table and false of the other.
        let d = null;
        try { d = await env.QUOTA_DB.prepare("DELETE FROM daily WHERE updated < ?1").bind(cutoff).run(); }
        catch (e) { console.error("DK RETENTION daily prune failed:", (e && e.message) || String(e)); }
        console.log("DK RETENTION pruned quota=" + ((r && r.meta && r.meta.changes) || 0) +
                    " daily=" + ((d && d.meta && d.meta.changes) || 0) + " row(s) older than 90 days");
      } catch (e) {
        console.error("DK RETENTION failed:", (e && e.message) || String(e));
      }
    })());

    // Overage billing. The reporter lives in its own Worker (datakoot-billing)
    // so the nine customer-facing servers never hold a Polar token. This is the
    // only thing that invokes it. The run is idempotent — it ships only what its
    // ledger has not already sent — so a retry or a double fire bills no one
    // twice. If the binding is missing, metering still works and nothing breaks.
    if (env.BILLING) {
      ctx.waitUntil(env.BILLING.fetch("https://billing/run", { method: "POST" }));
    }
  },
};

/* MCP protocol negotiation.
 *
 * Echo back the version the client asked for when we speak it, otherwise answer
 * with the newest one we do. These servers answered a hardcoded "2024-11-05" to
 * every client, which meant no client could rely on structuredContent or
 * outputSchema — both introduced in 2025-06-18. Same list and same behaviour as
 * base-intel and domain-intel, which already did this correctly.
 */
const DK_PROTOCOL_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"];
function dkProto(params) {
  const want = params && params.protocolVersion;
  return DK_PROTOCOL_VERSIONS.indexOf(want) !== -1 ? want : DK_PROTOCOL_VERSIONS[0];
}

/* Retention analytics.
 *
 * `quota` keeps ONE row per caller and overwrites it when the day rolls over,
 * so it can only ever show a caller's most recent active day. That makes the
 * most valuable question — did anyone come back tomorrow? — structurally
 * unanswerable. `daily` keeps one row per caller PER DAY instead.
 *
 * It stores exactly what `quota` stores: the same keyed, non-reversible caller
 * identifier, a date, a count. No queries, no addresses, nothing new about
 * anyone. The 04:17 retention job prunes it on the same 90-day clock, so the
 * privacy policy stays true.
 *
 * Wrapped so it can never break a caller's request: if this write fails the
 * call still succeeds and metering is unaffected. It is analytics, not billing.
 */
const DK_DAILY_SQL =
  "INSERT INTO daily (k, period, n, updated) VALUES (?1, ?2, 1, ?3) " +
  "ON CONFLICT(k, period) DO UPDATE SET n = daily.n + 1, updated = excluded.updated";
async function dkDaily(env, k, period) {
  try {
    await env.QUOTA_DB.prepare(DK_DAILY_SQL)
      .bind(k, period, Math.floor(Date.now() / 1000)).run();
  } catch (e) { /* never let analytics break a paying or free call */ }
}

/* Does this package actually exist?
 *
 * OSV answers "no known vulnerabilities" for a package that does not exist,
 * and to a calling agent that reads as "safe". On a security tool that is the
 * most dangerous failure available: a typo'd dependency, or a package name an
 * LLM invented, comes back with a clean bill of health. (Try `lodahs` against
 * OSV and you get a malware advisory; try a typo OSV has never heard of and
 * you get silence that looks like safety.)
 *
 * So whenever OSV returns nothing, we ask the ecosystem's own registry whether
 * the name is real. This FAILS SAFE: unreachable registry or unmapped
 * ecosystem returns null, and the caller is told the name is unverified rather
 * than told it does not exist.
 */
const DK_REGISTRY = {
  "npm":       (n) => "https://registry.npmjs.org/" + n.split("/").map(encodeURIComponent).join("/"),
  "PyPI":      (n) => "https://pypi.org/pypi/" + encodeURIComponent(n) + "/json",
  "crates.io": (n) => "https://crates.io/api/v1/crates/" + encodeURIComponent(n),
  "RubyGems":  (n) => "https://rubygems.org/api/v1/gems/" + encodeURIComponent(n) + ".json",
  "Packagist": (n) => "https://repo.packagist.org/p2/" + n + ".json",
  "NuGet":     (n) => "https://api.nuget.org/v3-flatcontainer/" + n.toLowerCase() + "/index.json",
  "Hex":       (n) => "https://hex.pm/api/packages/" + encodeURIComponent(n),
  "Pub":       (n) => "https://pub.dev/api/packages/" + encodeURIComponent(n),
};
async function dkPackageExists(eco, name) {
  const mk = DK_REGISTRY[eco];
  if (!mk || !name || typeof name !== "string") return null;
  try {
    const r = await fetch(mk(name), {
      headers: { "User-Agent": "Datakoot/1.0 (+https://datakoot.com)", Accept: "application/json" },
      cf: { cacheTtl: 3600, cacheEverything: true },
    });
    if (r.status === 404) return false;
    if (r.ok) return true;
    return null;
  } catch (e) { return null; }
}
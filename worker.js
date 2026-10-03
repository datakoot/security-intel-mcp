const POLAR_ORG = "7f455043-0b15-4a1c-b7a0-9c06c9f3b95e";
const CHECKOUT = "https://buy.polar.sh/polar_cl_Q9y3qLrNbtsssN3w5m8SK56oNcruwrmxLEPnd34oAZf";
const FREE_LIMIT = 100;          // anonymous, keyless, per UTC day
const PRO_INCLUDED = 50000;      // calls included in Pro each month
const UA = "Datakoot-Security-Intel/1.0 (+https://datakoot.com; contact@datakoot.com)";
const SERVER = { name: "security-intel", version: "2.1.0" };
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
  const isGet = method === "GET" && !body;
  const cache = caches.default;
  const ckey = new Request(url, { method: "GET" });
  if (isGet) { const hit = await cache.match(ckey); if (hit) { try { return await hit.json(); } catch (e) {} } }
  // Cache miss (or a POST): this call WILL hit the origin, so it counts against the breaker.
  const up = dkUpstreamFor(url);
  if (up) { const n = await dkUpstreamCount(up); if (n !== null && n > up.limit) return dkBusy(up); }
  const opt = { method, headers: { "User-Agent": UA, Accept: "application/json" } };
  if (body) { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body); }
  let r = await fetch(url, opt); if (!r.ok && (r.status === 403 || r.status === 429 || r.status === 503)) { await new Promise((s) => setTimeout(s, 700)); r = await fetch(url, opt); }
  if (r.status === 404) return { _notfound: true };
  if (!r.ok) return { _error: `upstream ${r.status}` };
  const txt = await r.text();
  if (isGet) { try { await cache.put(ckey, new Response(txt, { headers: { "Content-Type": "application/json", "Cache-Control": "max-age=" + ttl } })); } catch (e) {} }
  try { return JSON.parse(txt); } catch (e) { return { _error: "bad json from upstream" }; }
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
// --- Global upstream circuit breaker (shared across all callers, colos and IPs) ---
// Caching (below, in getJSON) absorbs repeated queries so they never touch a
// source. This breaker caps how fast DISTINCT queries can reach the rate-sensitive
// sources, so no flood — from any number of agents or rotating IPs — can push us
// past a source's published limit and get Datakoot blocked. Counts ONLY origin
// hits (cache misses). Trips into an honest "briefly busy, retry" — never fake data.
let DK_QDB = null;
const DK_UP_LIMITS = [
  { host: "services.nvd.nist.gov", key: "nvd", win: 30, limit: 4 },   // NVD allows ~5 / 30s without a key
  { host: "api.osv.dev",          key: "osv", win: 10, limit: 80 },
  { host: "www.cisa.gov",         key: "kev", win: 60, limit: 30 },   // KEV is a static feed, cached 6h; this is just a courtesy cap
  { host: "api.first.org",        key: "epss", win: 10, limit: 40 },  // FIRST EPSS fair use
];
function dkUpstreamFor(url) {
  try { const h = new URL(url).hostname; for (const x of DK_UP_LIMITS) if (x.host === h) return x; return null; }
  catch (e) { return null; }
}
const DK_UP_SQL = "INSERT INTO upstream_rl (k, n, exp) VALUES (?1, 1, ?2) ON CONFLICT(k) DO UPDATE SET n = n + 1 RETURNING n";
async function dkUpstreamCount(u) {
  if (!DK_QDB) return null;                       // no D1 bound -> fail open, never break the API
  const now = Math.floor(Date.now() / 1000);
  const bucket = Math.floor(now / u.win);
  try {
    const row = await DK_QDB.prepare(DK_UP_SQL).bind("up:" + u.key + ":" + bucket, (bucket + 1) * u.win).first();
    return row && typeof row.n === "number" ? row.n : null;
  } catch (e) { return null; }                    // D1 error -> fail open
}
function dkBusy(u) {
  return { _busy: true, _error: "Datakoot is briefly pausing calls to " + u.key.toUpperCase() +
    " to stay within its fair-use rate limit. This is a short, deliberate pause on our side, NOT an outage and NOT a statement about your query — retry in a few seconds." };
}
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
    // Pro: 50,000 calls a month, no daily limit. When the month's bucket is spent
    // we do NOT cut a paying customer off -- they soft-fall-back to the free tier
    // (100/day) for the rest of the month, or top up. Never a hard wall.
    if (env.QUOTA_DB) {
      try {
        const month = new Date().toISOString().slice(0, 7);
        const used = await bump(env, "pro:" + (await sha96("dk1:" + key)), month);
        if (used <= PRO_INCLUDED)
          return { ok: true, pro: true, used, included: PRO_INCLUDED, remaining: PRO_INCLUDED - used, limit: null };
        // bucket spent -> fall through to the free-tier check below (soft fallback)
      } catch (e) { console.error("QUOTA error (pro):", e && e.message); return { ok: true, pro: true, remaining: null, limit: null }; }
    } else {
      return { ok: true, pro: true, remaining: null, limit: null };
    }
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

/* CISA Known Exploited Vulnerabilities (KEV) — the authoritative list of CVEs
 * confirmed exploited in the wild. Public domain, updated ~daily. A big static
 * feed, so it is cached hard (6h) and rarely touches origin. */
async function kevCatalog() {
  const d = await getJSON("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", { ttl: 21600 });
  if (d._error || d._busy || !Array.isArray(d.vulnerabilities)) return null;
  return d;
}
function kevEntry(cat, id) {
  if (!cat) return null;
  const e = cat.vulnerabilities.find((v) => String(v.cveID || "").toUpperCase() === id);
  if (!e) return null;
  return {
    listed: true, vendor: e.vendorProject, product: e.product, name: e.vulnerabilityName,
    date_added: e.dateAdded, due_date: e.dueDate,
    known_ransomware_use: e.knownRansomwareCampaignUse === "Known",
    required_action: e.requiredAction,
  };
}
/* FIRST.org EPSS — probability (0-1) a CVE is exploited in the next 30 days,
 * plus its percentile among all scored CVEs. Free, keyless. */
async function epssFor(ids) {
  const q = ids.map((x) => String(x).toUpperCase()).join(",");
  const d = await getJSON("https://api.first.org/data/v1/epss?cve=" + encodeURIComponent(q), { ttl: 10800 });
  if (d._error || d._busy || !Array.isArray(d.data)) return null;
  const m = {};
  for (const r of d.data) m[String(r.cve).toUpperCase()] = { epss: parseFloat(r.epss), percentile: parseFloat(r.percentile), date: r.date };
  return m;
}

/* ------------------------------------------------------------------- tools */
const DK_AD = {"*.ecosystem":"Package registry to look in. One of: npm, pypi, cargo, go, maven, rubygems, nuget, composer, pub, hex.","*.name":"Exact package name as published in that registry, e.g. lodash for npm, requests for pypi."};
function dkDescribe(ts) { try { for (const t of ts) { const p = ((t.inputSchema || {}).properties) || {}; for (const k of Object.keys(p)) { const d = DK_AD[t.name + "." + k] || DK_AD["*." + k]; if (d && p[k] && !p[k].description) p[k].description = d; } } } catch (e) {} return ts; }
const TOOLS = [
  {
    name: "cve_lookup",
    description: "Look up a CVE by ID and get a compact summary: description, CVSS score & severity, vector, CWE weakness, publish date, references — plus whether it is on the CISA Known-Exploited list (actively exploited in the wild) and its EPSS exploit-probability. Sources: NVD (NIST), CISA KEV, FIRST EPSS.",
    inputSchema: { type: "object", properties: { cve_id: { type: "string", description: "e.g. CVE-2021-44228" } }, required: ["cve_id"] },
  },
  {
    name: "known_exploited",
    description: "Check whether a CVE is on the CISA Known Exploited Vulnerabilities (KEV) catalog — confirmed exploited in the wild — or list the most recently added exploited vulnerabilities. Pass cve_id to check one; omit it to list recent (optionally filter by vendor/product, or ransomware_only). Source: CISA KEV, updated ~daily.",
    inputSchema: { type: "object", properties: { cve_id: { type: "string", description: "Optional. Check a single CVE, e.g. CVE-2021-44228." }, limit: { type: "number", description: "When listing, how many newest entries to return (default 20, max 100)." }, vendor: { type: "string", description: "Optional. Filter by vendor or product name substring." }, ransomware_only: { type: "boolean", description: "Optional. Only vulns CISA links to known ransomware campaigns." } }, required: [] },
  },
  {
    name: "epss_score",
    description: "Get the EPSS exploit-probability score (0-1) and percentile for one or more CVEs — the likelihood each is exploited in the next 30 days. Use it to prioritize patching. Pass cve_id for one, or cve_ids (array or comma-separated) for many. Source: FIRST.org EPSS.",
    inputSchema: { type: "object", properties: { cve_id: { type: "string", description: "A single CVE id." }, cve_ids: { type: "array", items: { type: "string" }, description: "Multiple CVE ids (or pass a comma-separated string)." } }, required: [] },
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
    const out = {
      id: c.id, status: c.vulnStatus,
      description: desc ? desc.value : null,
      cvss: cvssFrom(c.metrics),
      cwe: (c.weaknesses || []).flatMap((w) => (w.description || []).map((x) => x.value)).filter((v) => v && v !== "NVD-CWE-noinfo").slice(0, 3),
      published: c.published, last_modified: c.lastModified,
      references: (c.references || []).slice(0, 5).map((r) => r.url),
    };
    // Enrich with real-world exploitation signal — the two questions triage actually turns on.
    const [cat, epssMap] = await Promise.all([kevCatalog(), epssFor([id])]);
    const kev = kevEntry(cat, id);
    out.known_exploited = kev || { listed: false, note: cat ? "Not on the CISA KEV catalog — not confirmed exploited by CISA. This does NOT prove it is not being exploited elsewhere." : "CISA KEV was unreachable; exploited-status unknown, not 'no'." };
    out.exploit_probability = (epssMap && epssMap[id]) || (epssMap ? { epss: null, percentile: null, note: "No EPSS score published (often a very new or rejected CVE)." } : null);
    out.sources = ["NVD / NIST (public domain)", "CISA KEV (public domain)", "FIRST.org EPSS"];
    return out;
  }
  if (name === "known_exploited") {
    const cat = await kevCatalog();
    if (!cat) return { error: "The CISA KEV catalog is temporarily unavailable upstream. This is NOT a statement that a CVE is not exploited — retry shortly." };
    if (args.cve_id) {
      const id = String(args.cve_id).toUpperCase().trim();
      if (!/^CVE-\d{4}-\d{4,}$/.test(id)) return { error: "Provide a valid CVE id, e.g. CVE-2021-44228." };
      const e = kevEntry(cat, id);
      return e
        ? { cve_id: id, ...e, catalog_version: cat.catalogVersion, source: "CISA KEV (public domain)" }
        : { cve_id: id, listed: false, note: "Not on the CISA Known Exploited Vulnerabilities catalog — CISA has not confirmed active exploitation. It does NOT guarantee the vulnerability is not being exploited anywhere.", source: "CISA KEV (public domain)" };
    }
    let limit = Math.max(1, Math.min(parseInt(args.limit, 10) || 20, 100));
    let vulns = cat.vulnerabilities.slice();
    if (args.vendor) { const vq = String(args.vendor).toLowerCase(); vulns = vulns.filter((v) => String(v.vendorProject || "").toLowerCase().includes(vq) || String(v.product || "").toLowerCase().includes(vq)); }
    if (args.ransomware_only) vulns = vulns.filter((v) => v.knownRansomwareCampaignUse === "Known");
    vulns.sort((a, b) => String(b.dateAdded || "").localeCompare(String(a.dateAdded || "")));
    const rows = vulns.slice(0, limit).map((v) => ({
      cve_id: v.cveID, vendor: v.vendorProject, product: v.product, name: v.vulnerabilityName,
      date_added: v.dateAdded, due_date: v.dueDate,
      known_ransomware_use: v.knownRansomwareCampaignUse === "Known",
      description: String(v.shortDescription || "").slice(0, 300),
    }));
    return {
      catalog_version: cat.catalogVersion, catalog_count: cat.count, released: cat.dateReleased,
      returned: rows.length, filter: { vendor: args.vendor || null, ransomware_only: !!args.ransomware_only },
      vulnerabilities: rows, source: "CISA KEV (public domain)",
    };
  }
  if (name === "epss_score") {
    let ids = [];
    if (Array.isArray(args.cve_ids)) ids = args.cve_ids;
    else if (typeof args.cve_ids === "string") ids = args.cve_ids.split(",");
    else if (args.cve_id) ids = [args.cve_id];
    ids = ids.map((x) => String(x).toUpperCase().trim()).filter((x) => /^CVE-\d{4}-\d{4,}$/.test(x)).slice(0, 100);
    if (!ids.length) return { error: "Provide 'cve_id', or 'cve_ids' (array or comma-separated), each like CVE-2021-44228." };
    const m = await epssFor(ids);
    if (!m) return { error: "EPSS is temporarily unavailable upstream. Retry shortly." };
    const scores = ids.map((id) => (m[id]
      ? { cve_id: id, epss: m[id].epss, percentile: m[id].percentile }
      : { cve_id: id, epss: null, percentile: null, note: "No EPSS score published for this CVE." }));
    return {
      model: "EPSS (FIRST.org)", as_of: (m[ids[0]] && m[ids[0]].date) || null,
      scored: scores.filter((s) => s.epss != null).length, scores,
      note: "EPSS = probability (0–1) the CVE is exploited in the next 30 days; percentile ranks it among all scored CVEs.",
      source: "FIRST.org EPSS",
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
      instructions: "Security Intel: vulnerability intelligence for AI agents — CVE lookups enriched with real-world exploitation signal (NVD + CISA Known-Exploited + EPSS), per-package known vulnerabilities and whole-manifest dependency audits (OSV), plus a live feed of what's actively exploited (known_exploited) and exploit-probability scoring (epss_score). Call audit_dependencies before trusting a project's dependency tree; use known_exploited + epss_score to prioritize what to patch first.",
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
        : `Daily free limit reached (${access.limit} calls). It resets at 00:00 UTC. Keep going right now with no account: $0.002 USDC per call via x402 at https://x402.datakoot.com/security/mcp (charged only on success). Or Datakoot Pro is ${PRO_INCLUDED.toLocaleString()} calls a month across all nine servers for $15 with no daily limit — ${CHECKOUT}`;
      return json(rpc(id, { content: [{ type: "text", text: msg }], isError: true }), 200, quotaHeaders(access));
    }
    const tname = params && params.name;
    const args = (params && params.arguments) || {};
    // The call was counted, so it reports the meter like any other response.
    if (!TOOLS.find((t) => t.name === tname)) return json(rpcErr(id, -32602, `Unknown tool: ${tname}`), 200, quotaHeaders(access)); { const _s = (TOOLS.find((t) => t.name === tname).inputSchema || {}).properties || {}; const _rq = ((TOOLS.find((t) => t.name === tname) || {}).inputSchema || {}).required || []; const _bad = Object.keys(args).filter((k) => !(k in _s)).map((k) => "unexpected '" + k + "'").concat(_rq.filter((k) => args[k] === undefined || args[k] === null || args[k] === "").map((k) => "missing required '" + k + "'")); if (_bad.length) return json(rpcErr(id, -32602, "Bad arguments for " + tname + ": " + _bad.join(", ") + ". Valid: " + (Object.keys(_s).join(", ") || "none") + ". The call was refused rather than ignoring them, because ignoring an argument returns a confident answer to a different question than the one asked."), 200, quotaHeaders(access)); }
    try {
      const out = await runTool(tname, args);
      const q = access.pro
        ? (access.used ? `${access.used.toLocaleString()} of ${PRO_INCLUDED.toLocaleString()} Pro calls used this month` : "")
        : (access.remaining == null ? "" : `${access.remaining} free calls left today`);
      const _h = quotaHeaders(access); if (q) _h["X-Datakoot-Quota"] = q;
      return json(rpc(id, { content: [{ type: "text", text: JSON.stringify(out, null, 2) }], isError: !!(out && out.error) }), 200, _h);
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
<meta name="description" content="Keyless MCP server giving AI agents vulnerability intelligence: CVE lookups enriched with CISA Known-Exploited status and EPSS exploit-probability (NVD + CISA KEV + FIRST), per-package known vulnerabilities and whole dependency-manifest audits (OSV).">
<style>${CSS}</style></head><body>
<header><a href="https://datakoot.com/" style="color:inherit"><div class="logo">${MARK}Data<span style="color:var(--accent)">koot</span></div></a>
<nav><a href="https://datakoot.com/">Datakoot</a><a href="#tools">Tools</a><a href="#start">Quick start</a><a href="#pricing">Pricing</a><a href="https://github.com/datakoot">GitHub</a></nav></header>
<div class="wrap">
<section class="hero"><h1>Know if your agent's dependencies are <span class="accent">vulnerable</span>.</h1>
<p class="sub">Security Intel gives AI agents vulnerability intelligence: look up any CVE — enriched with whether it's <em>actively exploited</em> (CISA KEV) and how likely it is to be (EPSS) — list what's newly exploited in the wild, score exploit-probability, and audit an entire dependency manifest in one call. NVD, CISA KEV, FIRST EPSS, OSV. No API keys.</p></section>

<section class="section" id="tools"><h2>Tools</h2><div class="grid">
<div class="card"><h3><code>cve_lookup</code></h3><p>CVE summary: CVSS, severity, CWE, references — plus is-it-exploited (CISA KEV) and exploit-probability (EPSS).</p></div>
<div class="card"><h3><code>known_exploited</code></h3><p>Is a CVE actively exploited in the wild, or list what CISA just added to the KEV catalog.</p></div>
<div class="card"><h3><code>epss_score</code></h3><p>EPSS exploit-probability (0–1) for one or many CVEs — patch the likely ones first.</p></div>
<div class="card"><h3><code>package_vulnerabilities</code></h3><p>Known vulnerabilities for a package/version (OSV).</p></div>
<div class="card"><h3><code>audit_dependencies</code></h3><p>Audit a whole package.json for vulnerabilities in one call.</p></div>
</div></section>

<section class="section" id="start"><h2>Quick start</h2>
<p class="sub">One line, no key. Works with Claude, Cursor, and any MCP client.</p>
<div class="cmd"><code>claude mcp add --transport http security-intel ${ep}</code></div>
<p style="color:var(--muted);font-size:14px">Or point any MCP client at <code>${ep}</code></p></section>

<section class="section" id="pricing"><h2>Pricing</h2><div class="tiers">
<div class="tier"><b>Free</b><span>100 calls / day</span><span>Every tool, no key, no signup.</span></div>
<div class="tier"><b>$15/mo · Pro</b><span>50,000 calls / month · no daily limit</span><span>One key unlocks all nine Datakoot servers. Full speed to 50k, then free-tier speed or top up — never cut off.</span><a class="btn" href="${CHECKOUT}">Upgrade</a></div>
</div></section>
</div>
<footer><a href="https://datakoot.com/" style="color:inherit">Datakoot</a> — infrastructure for the agent economy · <a href="https://github.com/datakoot">GitHub</a> · Data: NVD/NIST (public domain), CISA KEV (public domain), FIRST.org EPSS, OSV.dev (CC-BY 4.0)</footer>
</body></html>`;
}

/* ------------------------------------------------------------------ router */
const __dkInner = {
  async fetch(request, env) {
    if (DK_SALT === null) DK_SALT = env.IP_SALT || "";
    if (DK_QDB === null) DK_QDB = env.QUOTA_DB || false;
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
    if (DK_QDB === null) DK_QDB = env.QUOTA_DB || false;
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
        try { await env.QUOTA_DB.prepare("DELETE FROM upstream_rl WHERE exp < ?1").bind(Math.floor(Date.now() / 1000)).run(); }
        catch (e) { console.error("DK RETENTION upstream_rl prune failed:", (e && e.message) || String(e)); }
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




/* ---- Datakoot agent metadata layer v2 (2026-10-03) ----
 * Wraps the server without touching tool logic:
 *  - tools/list: title, MCP annotations (read-only lookups), sharper descriptions where needed,
 *    and an outputSchema listing the fields each tool returns.
 *  - tools/call: forgiving inputs (common agent mistakes are normalised before the tool sees them)
 *    and structuredContent (the parsed JSON object) on every successful result.
 * Anything that is not a JSON tools/list or tools/call exchange passes through byte-for-byte.
 */
const __DK_EXTRA = {"cve_lookup":{"outputKeys":["id","status","description","cvss","cwe","published","last_modified","references","known_exploited","exploit_probability","sources"],"params":{"cve_id":"CVE identifier, e.g. CVE-2021-44228 (case-insensitive; a bare 2021-44228 also works)."}},"known_exploited":{"outputKeys":["catalog_version","catalog_count","released","returned","filter","vulnerabilities","source","cve_id","listed","vendor","product","name","date_added","due_date","known_ransomware_use","required_action"]},"epss_score":{"outputKeys":["model","as_of","scored","scores","note","source"]},"package_vulnerabilities":{"outputKeys":["ecosystem","name","version","vulnerability_count","vulnerabilities","source"]},"audit_dependencies":{"outputKeys":["ecosystem","packages_audited","packages_with_vulnerabilities","total_vulnerabilities","packages_not_found","packages_unverified","verdict","findings","source"],"params":{"ecosystem":"Package registry for the dependencies: npm (default), pypi, cargo, go, maven, rubygems, nuget, composer, pub, or hex."}}};
const __DK_COUNTRIES = null;
const __DK_ACRONYMS = { cve: "CVE", epss: "EPSS", fx: "FX", dns: "DNS", us: "US", sec: "SEC", rdap: "RDAP", url: "URL", ip: "IP" };
const __DK_STATES = { alabama: "AL", alaska: "AK", arizona: "AZ", arkansas: "AR", california: "CA", colorado: "CO", connecticut: "CT", delaware: "DE", "district of columbia": "DC", "washington dc": "DC", florida: "FL", georgia: "GA", hawaii: "HI", idaho: "ID", illinois: "IL", indiana: "IN", iowa: "IA", kansas: "KS", kentucky: "KY", louisiana: "LA", maine: "ME", maryland: "MD", massachusetts: "MA", michigan: "MI", minnesota: "MN", mississippi: "MS", missouri: "MO", montana: "MT", nebraska: "NE", nevada: "NV", "new hampshire": "NH", "new jersey": "NJ", "new mexico": "NM", "new york": "NY", "north carolina": "NC", "north dakota": "ND", ohio: "OH", oklahoma: "OK", oregon: "OR", pennsylvania: "PA", "rhode island": "RI", "south carolina": "SC", "south dakota": "SD", tennessee: "TN", texas: "TX", utah: "UT", vermont: "VT", virginia: "VA", washington: "WA", "west virginia": "WV", wisconsin: "WI", wyoming: "WY", "puerto rico": "PR", guam: "GU", "american samoa": "AS", "virgin islands": "VI", "us virgin islands": "VI", "northern mariana islands": "MP" };

function __dkTitle(name) {
  return String(name).split("_").map((w) => __DK_ACRONYMS[w] || (w.charAt(0).toUpperCase() + w.slice(1))).join(" ");
}
function __dkDecorate(tool) {
  if (!tool || typeof tool !== "object" || !tool.name) return tool;
  const x = __DK_EXTRA[tool.name] || {};
  const title = tool.title || __dkTitle(tool.name);
  const out = Object.assign({}, tool, { title });
  if (x.description) out.description = x.description;
  if (x.params && out.inputSchema && out.inputSchema.properties) {
    const props = Object.assign({}, out.inputSchema.properties);
    for (const k of Object.keys(x.params)) if (props[k]) props[k] = Object.assign({}, props[k], { description: x.params[k] });
    out.inputSchema = Object.assign({}, out.inputSchema, { properties: props });
  }
  if (!out.outputSchema && Array.isArray(x.outputKeys) && x.outputKeys.length) {
    const p = {}; for (const k of x.outputKeys) p[k] = {};
    out.outputSchema = { type: "object", properties: p, additionalProperties: true };
  }
  out.annotations = Object.assign({ title, readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true }, tool.annotations || {});
  return out;
}

const __dkTrim = (v) => (typeof v === "string" ? v.trim() : v);
function __dkIsoDate(v) {
  if (typeof v !== "string") return v;
  const s = v.trim(); let m;
  if ((m = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/))) return m[3] + "-" + m[1].padStart(2, "0") + "-" + m[2].padStart(2, "0");
  if ((m = s.match(/^(\d{4})[\/.](\d{1,2})[\/.](\d{1,2})$/))) return m[1] + "-" + m[2].padStart(2, "0") + "-" + m[3].padStart(2, "0");
  return s;
}
function __dkCve(v) {
  if (typeof v !== "string") return v;
  const s = v.trim();
  return /^\d{4}-\d{4,}$/.test(s) ? "CVE-" + s : s;
}
function __dkCountry(v) {
  if (typeof v !== "string" || !__DK_COUNTRIES) return v;
  const s = v.trim();
  if (/^[A-Za-z]{2}$/.test(s)) return s.toUpperCase();
  const hit = __DK_COUNTRIES[s.toLowerCase()];
  return hit || s;
}
function __dkNormalize(name, a) {
  if (!a || typeof a !== "object" || Array.isArray(a)) return a;
  const o = Object.assign({}, a);
  for (const k of Object.keys(o)) o[k] = __dkTrim(o[k]);
  if ((name === "cve_lookup" || name === "known_exploited" || name === "epss_score") && o.cve_id) o.cve_id = __dkCve(o.cve_id);
  if (name === "epss_score" && o.cve_ids) {
    const list = Array.isArray(o.cve_ids) ? o.cve_ids : String(o.cve_ids).split(",");
    o.cve_ids = list.map(__dkCve);
  }
  if (typeof o.ecosystem === "string") {
    o.ecosystem = o.ecosystem.toLowerCase();
    if (o.ecosystem === "npm" && typeof o.name === "string" && !o.name.startsWith("@")) o.name = o.name.toLowerCase();
  }
  if (o.country) o.country = __dkCountry(o.country);
  if (Array.isArray(o.countries)) o.countries = o.countries.map(__dkCountry);
  if (name === "fx_historical" && o.date) o.date = __dkIsoDate(o.date);
  if (name === "fx_timeseries") { if (o.start) o.start = __dkIsoDate(o.start); if (o.end) o.end = __dkIsoDate(o.end); }
  if (name === "weather_alerts" && typeof o.area === "string") { const st = __DK_STATES[o.area.toLowerCase()]; o.area = st || (/^[a-z]{2}$/i.test(o.area) ? o.area.toUpperCase() : o.area); }
  if (name === "tx_status" && typeof o.hash === "string" && /^[0-9a-fA-F]{64}$/.test(o.hash)) o.hash = "0x" + o.hash;
  return o;
}
function __dkTitleCase(s) {
  return String(s).trim().replace(/\s+/g, " ").split(" ").map((w) => (/^[a-z]{2}$/i.test(w) && w === w.toLowerCase() && w.length === 2 ? w.toUpperCase() : w.charAt(0).toUpperCase() + w.slice(1).toLowerCase())).join(" ");
}

function __dkWithBody(request, body) {
  const h = new Headers(request.headers); h.delete("content-length");
  return new Request(request.url, { method: "POST", headers: h, body: JSON.stringify(body) });
}
async function __dkJson(res) {
  const ct = res.headers.get("content-type") || "";
  if (!ct.includes("application/json")) return null;
  try { return await res.clone().json(); } catch (e) { return null; }
}
function __dkRespond(res, body) {
  const h = new Headers(res.headers); h.delete("content-length");
  return new Response(JSON.stringify(body), { status: res.status, statusText: res.statusText, headers: h });
}
function __dkAddStructured(body) {
  const r = body && body.result;
  if (!r || r.isError || r.structuredContent !== undefined || !Array.isArray(r.content) || !r.content[0] || r.content[0].type !== "text") return false;
  try {
    const parsed = JSON.parse(r.content[0].text);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) { r.structuredContent = parsed; return true; }
  } catch (e) {}
  return false;
}

async function __dkWrappedFetch(request, env, ctx) {
  let msg = null;
  if (request.method === "POST") {
    try { const peek = await request.clone().json(); if (peek && !Array.isArray(peek)) msg = peek; } catch (e) { msg = null; }
  }
  const method = msg && msg.method;
  if (method !== "tools/list" && method !== "tools/call") return __dkInner.fetch(request, env, ctx);

  if (method === "tools/list") {
    const res = await __dkInner.fetch(request, env, ctx);
    const body = await __dkJson(res);
    if (!body || !body.result || !Array.isArray(body.result.tools)) return res;
    body.result.tools = body.result.tools.map(__dkDecorate);
    return __dkRespond(res, body);
  }

  // tools/call
  const name = msg.params && msg.params.name;
  let req = request;
  try {
    const args = (msg.params && msg.params.arguments) || {};
    const norm = __dkNormalize(name, args);
    if (JSON.stringify(norm) !== JSON.stringify(args)) req = __dkWithBody(request, Object.assign({}, msg, { params: Object.assign({}, msg.params, { arguments: norm }) }));
  } catch (e) { req = request; }
  let res = await __dkInner.fetch(req, env, ctx);
  let body = await __dkJson(res);
  // geocode: the Census place gazetteer is case-sensitive; retry once with proper capitalisation.
  if (name === "geocode" && body && body.result && body.result.isError) {
    const addr = msg.params && msg.params.arguments && msg.params.arguments.address;
    const fixed = typeof addr === "string" ? __dkTitleCase(addr) : null;
    if (fixed && fixed !== addr) {
      const res2 = await __dkInner.fetch(__dkWithBody(request, Object.assign({}, msg, { params: Object.assign({}, msg.params, { arguments: Object.assign({}, msg.params.arguments, { address: fixed }) }) })), env, ctx);
      const body2 = await __dkJson(res2);
      if (body2 && body2.result && !body2.result.isError) { res = res2; body = body2; }
    }
  }
  if (!body) return res;
  return __dkAddStructured(body) ? __dkRespond(res, body) : res;
}
export default Object.assign({}, __dkInner, { fetch: __dkWrappedFetch });

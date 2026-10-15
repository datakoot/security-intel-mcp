#!/usr/bin/env python3
"""Weekly candidate list for a 'will it be added to CISA KEV within 30 days?' forecast pilot.
Candidates: the N highest-EPSS CVEs with a current-year ID that are not yet in the KEV catalog.
Baseline forecast for each = its EPSS score (FIRST: probability of exploitation activity in the next 30 days).
Stdlib only. Usage: python3 kev_candidates.py [N=10]"""
import json,sys,urllib.request,datetime as dt
UA={"User-Agent":"datakoot-kev-candidates/0.2 (+https://datakoot.com)"}
get=lambda u: json.load(urllib.request.urlopen(urllib.request.Request(u,headers=UA),timeout=90))
N=int(sys.argv[1]) if len(sys.argv)>1 else 10
today=dt.datetime.now(dt.timezone.utc).date(); yr=f"CVE-{today.year}-"
kev=get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
inkev={v["cveID"] for v in kev["vulnerabilities"]}
cands=[];off=0
while len(cands)<N and off<50000:
    page=get(f"https://api.first.org/data/v1/epss?order=!epss&limit=5000&offset={off}")["data"]; off+=5000
    if not page: break
    for r in page:
        if r["cve"].startswith(yr) and r["cve"] not in inkev:
            cands.append({"cve":r["cve"],"epss_baseline":float(r["epss"]),"percentile":float(r["percentile"]),"epss_date":r["date"]})
            if len(cands)>=N: break
close=today+dt.timedelta(days=30)
print(json.dumps({"opens":str(today),"closes":str(close),"kev_catalog_at_open":kev["catalogVersion"],
 "question":f"Will <cve> be added to the CISA KEV catalog on or before {close} (UTC, by dateAdded)?",
 "settlement":"YES iff the CVE appears in the KEV JSON/CSV feed with dateAdded <= closes (first published value).",
 "candidates":cands},indent=2))

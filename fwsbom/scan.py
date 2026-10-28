# Copyright 2026 Chen Embedded Software LLC
# SPDX-License-Identifier: Apache-2.0
"""Look up known vulnerabilities for detected components in the NVD (CVE API 2.0).

Uses each component's CPEs with `virtualMatchString`, which also matches CVEs whose affected
configuration is a version range. NVD marks CVEs in the CISA Known Exploited Vulnerabilities
catalog with `cisaExploitAdd`, so "actively exploited" comes from the same response.

Results mean "this version is listed as affected", not "this product is exploitable".
"""
import json
import os
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"]


@dataclass
class Vuln:
    id: str
    severity: str = "UNKNOWN"
    score: Optional[float] = None
    exploited: bool = False
    fixed_in: List[str] = field(default_factory=list)
    description: str = ""


def _delay(nvd_key):
    return 0.7 if nvd_key else 6.5  # NVD public rate limit: 5 requests / 30 s without a key


def _http_get(url, nvd_key):
    req = urllib.request.Request(url, headers={"User-Agent": "fwsbom"})
    if nvd_key:
        req.add_header("apiKey", nvd_key)
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.load(resp)


def _severity(metrics):
    for name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        for m in metrics.get(name) or []:
            d = m.get("cvssData", {})
            if d.get("baseSeverity"):
                return d["baseSeverity"].upper(), d.get("baseScore")
    for m in metrics.get("cvssMetricV2") or []:
        if m.get("baseSeverity"):
            return m["baseSeverity"].upper(), m.get("cvssData", {}).get("baseScore")
    return "UNKNOWN", None


def _fixed_versions(cve, product):
    out = []
    for conf in cve.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                if m.get("vulnerable") and (":%s:" % product) in m.get("criteria", "") and m.get("versionEndExcluding"):
                    if m["versionEndExcluding"] not in out:
                        out.append(m["versionEndExcluding"])
    return out


def parse(response, product):
    out = []
    for item in response.get("vulnerabilities") or []:
        cve = item.get("cve", {})
        sev, score = _severity(cve.get("metrics") or {})
        desc = next((d["value"] for d in cve.get("descriptions") or [] if d.get("lang") == "en"), "")
        out.append(Vuln(id=cve.get("id", "?"), severity=sev, score=score,
                        exploited=bool(cve.get("cisaExploitAdd")),
                        fixed_in=_fixed_versions(cve, product), description=desc))
    return out


def lookup(cpes, nvd_key=None, get=None, sleep=None):
    """All CVEs for any of the component's CPEs, de-duplicated, worst first."""
    get = get or _http_get
    sleep = sleep or time.sleep
    found: Dict[str, Vuln] = {}
    first = True
    for cpe in cpes:
        product = cpe.split(":")[4] if cpe.count(":") >= 5 else ""
        start = 0
        while True:
            if not first:
                sleep(_delay(nvd_key))
            first = False
            q = urllib.parse.urlencode({"virtualMatchString": cpe, "resultsPerPage": 2000, "startIndex": start})
            resp = get(NVD_URL + "?" + q, nvd_key)
            for v in parse(resp, product):
                if v.id not in found:
                    found[v.id] = v
                else:
                    found[v.id].fixed_in = sorted(set(found[v.id].fixed_in) | set(v.fixed_in))
            page = resp.get("resultsPerPage") or 0
            start += page
            if not page or start >= (resp.get("totalResults") or 0):
                break
    return sorted(found.values(), key=lambda v: (not v.exploited,
                                                 SEVERITY_ORDER.index(v.severity) if v.severity in SEVERITY_ORDER else 9,
                                                 -(v.score or 0)))


def scan(components, nvd_key=None, get=None, sleep=None, progress=None):
    """Attach `.vulns` to each component (None = not checked). Components known NOT to be linked are skipped."""
    sleep = sleep or time.sleep
    nvd_key = nvd_key or os.environ.get("NVD_API_KEY")
    first = True
    for c in components:
        c.vulns = None
        if c.linked is False or not c.cpes:
            continue
        if not first:
            sleep(_delay(nvd_key))
        first = False
        if progress:
            progress(c)
        c.vulns = lookup(c.cpes, nvd_key, get, sleep)
    return components


def summary(vulns):
    if vulns is None:
        return "-"
    if not vulns:
        return "none known"
    counts = {}
    for v in vulns:
        counts[v.severity] = counts.get(v.severity, 0) + 1
    parts = ["%d %s" % (counts[s], s.lower()) for s in SEVERITY_ORDER if s in counts]
    ex = sum(v.exploited for v in vulns)
    return "%d (%s)%s" % (len(vulns), ", ".join(parts), "  ACTIVELY EXPLOITED: %d" % ex if ex else "")


def version_key(v):
    """Sort key for version strings like 2.16.12, r0.15, V10.4.3."""
    import re
    return [int(x) for x in re.findall(r"\d+", v)] or [0]


def worst(vulns):
    """Index into SEVERITY_ORDER of the worst finding (len() if none)."""
    idx = [SEVERITY_ORDER.index(v.severity) for v in vulns or [] if v.severity in SEVERITY_ORDER]
    return min(idx) if idx else len(SEVERITY_ORDER)

# Copyright 2026 Chen Embedded Software LLC
# SPDX-License-Identifier: Apache-2.0
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr
from unittest import mock

from fwsbom import cli, scan
from fwsbom.detectors import Component


def cve(cid, sev, score=7.5, kev=False, fixed=None, product="mbed_tls"):
    item = {"cve": {"id": cid, "descriptions": [{"lang": "en", "value": cid + " description"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": sev, "baseScore": score}}]}}}
    if kev:
        item["cve"]["cisaExploitAdd"] = "2026-01-01"
    if fixed:
        item["cve"]["configurations"] = [{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:arm:%s:*:*:*:*:*:*:*:*" % product,
             "versionEndExcluding": fixed}]}]}]
    return item


def response(*items):
    return {"resultsPerPage": len(items), "startIndex": 0, "totalResults": len(items),
            "vulnerabilities": list(items)}


class ScanTest(unittest.TestCase):
    def test_parse_severity_kev_and_fix(self):
        v = scan.parse(response(cve("CVE-1", "CRITICAL", 9.8, kev=True, fixed="2.28.0")), "mbed_tls")[0]
        self.assertEqual((v.id, v.severity, v.score, v.exploited, v.fixed_in),
                         ("CVE-1", "CRITICAL", 9.8, True, ["2.28.0"]))

    def test_lookup_merges_cpes_dedups_and_sorts(self):
        calls = []

        def get(url, key):
            calls.append(url)
            if "trustedfirmware" in url:
                return response(cve("CVE-2", "HIGH"), cve("CVE-3", "MEDIUM", 5.0))
            return response(cve("CVE-1", "LOW", 2.0), cve("CVE-2", "HIGH"), cve("CVE-4", "MEDIUM", kev=True))
        vs = scan.lookup(["cpe:2.3:a:arm:mbed_tls:2.16.0:*:*:*:*:*:*:*",
                          "cpe:2.3:a:trustedfirmware:mbed_tls:2.16.0:*:*:*:*:*:*:*"], get=get, sleep=lambda s: None)
        self.assertEqual([v.id for v in vs], ["CVE-4", "CVE-2", "CVE-3", "CVE-1"])  # exploited first, then severity
        self.assertEqual(len(calls), 2)

    def test_pagination(self):
        pages = [dict(response(cve("CVE-1", "HIGH")), totalResults=2),
                 dict(response(cve("CVE-2", "LOW")), totalResults=2, startIndex=1)]
        vs = scan.lookup(["cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"], get=lambda u, k: pages.pop(0), sleep=lambda s: None)
        self.assertEqual({v.id for v in vs}, {"CVE-1", "CVE-2"})

    def test_scan_skips_unlinked_and_cpe_less(self):
        a = Component("A", "1", "s", "/a", cpes=["cpe:2.3:a:x:a:1:*:*:*:*:*:*:*"], linked=True)
        b = Component("B", "1", "s", "/b", cpes=["cpe:2.3:a:x:b:1:*:*:*:*:*:*:*"], linked=False)
        c = Component("C", "1", "s", "/c")
        scan.scan([a, b, c], get=lambda u, k: response(cve("CVE-9", "HIGH")), sleep=lambda s: None)
        self.assertEqual([v.id for v in a.vulns], ["CVE-9"])
        self.assertIsNone(b.vulns)
        self.assertIsNone(c.vulns)
        self.assertEqual(scan.summary(a.vulns), "1 (1 high)")
        self.assertEqual(scan.summary([]), "none known")

    def test_cli_scan_writes_vulnerabilities_and_fail_on(self):
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "mbedtls", "include", "mbedtls"))
            with open(os.path.join(root, "mbedtls", "include", "mbedtls", "build_info.h"), "w") as fh:
                fh.write('#define MBEDTLS_VERSION_STRING "2.16.0"\n')
            out = os.path.join(root, "sbom.json")
            fake = response(cve("CVE-2021-44732", "CRITICAL", 9.8, fixed="2.16.12"), cve("CVE-X", "LOW", 2.0))
            with mock.patch.object(scan, "_http_get", lambda u, k: fake), \
                    mock.patch.object(scan.time, "sleep", lambda s: None), redirect_stderr(io.StringIO()) as err:
                rc_ok = cli.main([root, "--scan", "-o", out])
                rc_fail = cli.main([root, "--scan", "--fail-on", "high", "-o", out])
                rc_kev = cli.main([root, "--scan", "--fail-on", "exploited", "-o", out])
            self.assertEqual((rc_ok, rc_fail, rc_kev), (0, 1, 0))
            self.assertIn("2 (1 critical, 1 low)", err.getvalue())
            with open(out) as fh:
                bom = json.load(fh)
            ids = {v["id"] for v in bom["vulnerabilities"]}
            self.assertEqual(ids, {"CVE-2021-44732", "CVE-X"})
            crit = next(v for v in bom["vulnerabilities"] if v["id"] == "CVE-2021-44732")
            self.assertEqual(crit["ratings"][0]["severity"], "critical")
            self.assertIn("2.16.12", crit["recommendation"])

    def test_fail_on_requires_scan(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            cli.main([".", "--fail-on", "high"])


if __name__ == "__main__":
    unittest.main()

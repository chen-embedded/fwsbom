# Copyright 2026 Chen Embedded Software LLC
# SPDX-License-Identifier: Apache-2.0
"""Render detected components as a CycloneDX 1.5 JSON SBOM."""
import datetime
import uuid
from typing import List

from . import __version__
from .detectors import Component


def render(components: List[Component], product: str, product_version: str, supplier: str) -> dict:
    comps = []
    for c in components:
        entry = {
            "type": "library",
            "bom-ref": c.purl or "{}@{}".format(c.name, c.version),
            "name": c.name,
            "version": c.version,
            "supplier": {"name": c.supplier},
            "purl": c.purl,
            "properties": [{"name": "fwsbom:evidence", "value": e} for e in c.evidence],
        }
        if c.license:
            entry["licenses"] = [{"expression": c.license}] if " OR " in c.license or "(" in c.license \
                else [{"license": {"id": c.license}}]
        if c.cpes:
            # Extra CPEs go in the property Syft/Grype read for alternate identifiers.
            entry["cpe"] = c.cpes[0]
            entry["properties"] += [{"name": "syft:cpe23", "value": x} for x in c.cpes[1:]]
        if c.linked is not None:
            entry["properties"].append({"name": "fwsbom:linked", "value": str(c.linked).lower()})
        comps.append(entry)

    vulns = []
    for c, entry in zip(components, comps):
        for v in getattr(c, "vulns", None) or []:
            item = {
                "id": v.id,
                "source": {"name": "NVD", "url": "https://nvd.nist.gov/vuln/detail/" + v.id},
                "ratings": [{"severity": v.severity.lower() if v.severity != "UNKNOWN" else "unknown",
                             **({"score": v.score} if v.score is not None else {})}],
                "description": v.description[:1000],
                "affects": [{"ref": entry["bom-ref"]}],
            }
            if v.fixed_in:
                item["recommendation"] = "Upgrade to {} or later.".format(" / ".join(v.fixed_in))
            if v.exploited:
                item["properties"] = [{"name": "fwsbom:cisa-kev", "value": "true"}]
            vulns.append(item)

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:{}".format(uuid.uuid4()),
        "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat(),
            "tools": {"components": [{"type": "application", "name": "fwsbom", "version": __version__,
                                      "supplier": {"name": "Chen Embedded Software LLC"}}]},
            "component": {"bom-ref": "root-firmware", "type": "firmware", "name": product, "version": product_version,
                          "supplier": {"name": supplier}},
        },
        "components": comps,
        "dependencies": [{"ref": "root-firmware", "dependsOn": [c["bom-ref"] for c in comps]}],
    }
    if vulns:
        bom["vulnerabilities"] = vulns
    return bom

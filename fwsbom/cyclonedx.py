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

    return {
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

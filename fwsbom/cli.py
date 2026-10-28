# Copyright 2026 Chen Embedded Software LLC
# SPDX-License-Identifier: Apache-2.0
"""fwsbom command line: scan a firmware tree, optionally confirm linkage, emit CycloneDX."""
import argparse
import json
import os
import sys

from . import __version__, cyclonedx, detectors, mapfile, scan


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="fwsbom",
        description="Generate a CycloneDX SBOM for bare-metal / RTOS C firmware projects.")
    ap.add_argument("root", help="firmware project root directory")
    ap.add_argument("--map", help="GNU ld linker map file; marks which components are actually linked")
    ap.add_argument("--linked-only", action="store_true",
                    help="drop components whose sources never reached the image (requires --map)")
    ap.add_argument("--name", default="firmware", help="product/firmware name")
    ap.add_argument("--version", dest="product_version", default="0.0.0", help="firmware version")
    ap.add_argument("--supplier", default="Unknown", help="your company name")
    ap.add_argument("-o", "--output", help="write SBOM here instead of stdout")
    ap.add_argument("--summary", action="store_true", help="print a human-readable table to stderr")
    ap.add_argument("--scan", action="store_true",
                    help="look up known vulnerabilities in the NVD (internet access; set NVD_API_KEY to go faster)")
    ap.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "exploited"],
                    help="with --scan: exit 1 if any finding is at least this severe (or actively exploited)")
    ap.add_argument("-V", action="version", version="fwsbom " + __version__)
    args = ap.parse_args(argv)

    if args.linked_only and not args.map:
        ap.error("--linked-only requires --map")
    if args.fail_on and not args.scan:
        ap.error("--fail-on requires --scan")

    comps = detectors.detect(args.root)
    if args.map:
        objs = mapfile.linked_objects(args.map)
        for c in comps:
            c.linked = mapfile.is_linked(c.root, objs) if c.linkable else None
        if args.linked_only:
            comps = [c for c in comps if c.linked is not False]

    if args.scan:
        todo = sum(1 for c in comps if c.linked is not False and c.cpes)
        print("Checking {} component(s) against the NVD{}...".format(
            todo, "" if os.environ.get("NVD_API_KEY") else " (about 7 s each; set NVD_API_KEY to go faster)"),
            file=sys.stderr)
        try:
            scan.scan(comps, progress=lambda c: print("  " + c.name, file=sys.stderr))
        except OSError as exc:
            print("fwsbom: vulnerability lookup failed ({}); SBOM written without scan results".format(exc),
                  file=sys.stderr)
            args.scan = False

    bom = cyclonedx.render(comps, args.name, args.product_version, args.supplier)
    text = json.dumps(bom, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    else:
        print(text)

    if args.summary or args.output or args.scan:
        linked_label = {True: "yes", False: "no", None: "?"}
        if args.scan:
            print("{:<28} {:<14} {:<7} {}".format("COMPONENT", "VERSION", "LINKED", "KNOWN VULNERABILITIES"),
                  file=sys.stderr)
            for c in comps:
                note = scan.summary(c.vulns)
                if c.linked is False:
                    note = "(not linked into the image, not checked)"
                elif c.vulns is None:
                    note = "(no CPE in NVD, not checked)"
                elif c.vulns:
                    fixes = sorted({f for v in c.vulns for f in v.fixed_in}, key=scan.version_key)
                    if fixes:
                        note += "; fixed versions include " + ", ".join(fixes[-3:])
                print("{:<28} {:<14} {:<7} {}".format(c.name, c.version, linked_label[c.linked], note),
                      file=sys.stderr)
            print("A listed vulnerability means the version is affected per NVD; whether your product is "
                  "exploitable depends on configuration and use.", file=sys.stderr)
        else:
            print("{:<28} {:<14} {:<7} {}".format("COMPONENT", "VERSION", "LINKED", "EVIDENCE"), file=sys.stderr)
            for c in comps:
                print("{:<28} {:<14} {:<7} {}".format(c.name, c.version, linked_label[c.linked], c.evidence[0]),
                      file=sys.stderr)
        print("{} component(s)".format(len(comps)), file=sys.stderr)

    if args.scan and args.fail_on:
        all_v = [v for c in comps for v in (c.vulns or [])]
        if args.fail_on == "exploited":
            bad = any(v.exploited for v in all_v)
        else:
            bad = scan.worst(all_v) <= scan.SEVERITY_ORDER.index(args.fail_on.upper())
        if bad:
            print("fwsbom: failing because of findings at or above '{}'".format(args.fail_on), file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

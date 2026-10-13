"""fwsbom command line: scan a firmware tree, optionally confirm linkage, emit CycloneDX."""
import argparse
import json
import sys

from . import __version__, cyclonedx, detectors, mapfile


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
    ap.add_argument("-V", action="version", version="fwsbom " + __version__)
    args = ap.parse_args(argv)

    if args.linked_only and not args.map:
        ap.error("--linked-only requires --map")

    comps = detectors.detect(args.root)
    if args.map:
        objs = mapfile.linked_objects(args.map)
        for c in comps:
            c.linked = mapfile.is_linked(c.root, objs) if c.linkable else None
        if args.linked_only:
            comps = [c for c in comps if c.linked is not False]

    bom = cyclonedx.render(comps, args.name, args.product_version, args.supplier)
    text = json.dumps(bom, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    else:
        print(text)

    if args.summary or args.output:
        linked_label = {True: "yes", False: "no", None: "?"}
        print("{:<28} {:<14} {:<7} {}".format("COMPONENT", "VERSION", "LINKED", "EVIDENCE"), file=sys.stderr)
        for c in comps:
            print("{:<28} {:<14} {:<7} {}".format(c.name, c.version, linked_label[c.linked], c.evidence[0]),
                  file=sys.stderr)
        print("{} component(s)".format(len(comps)), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

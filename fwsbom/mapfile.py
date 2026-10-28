# Copyright 2026 Chen Embedded Software LLC
# SPDX-License-Identifier: Apache-2.0
"""Use a GNU ld / arm-none-eabi linker map file to tell which components actually ship.

Source scanning alone over-reports: a vendored library sitting in the tree may never
be compiled or may be dropped by --gc-sections. The map file lists every object
that contributed a section to the final image, which is what the SBOM should describe.
"""
import os
import re
from typing import Iterable, Optional, Set

# Object references look like: "path/to/foo.o", "libfoo.a(bar.o)", "foo.c.obj"
_OBJ_RE = re.compile(r"([^\s()]+?\.(?:o|obj))\b|\(([^()\s]+?\.(?:o|obj))\)")


def linked_objects(map_path: str) -> Set[str]:
    """Return the set of object basenames (without .o/.obj, without .c/.cpp) that
    contributed code or data to the image."""
    objs = set()
    in_discarded = False
    with open(map_path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("Discarded input sections"):
                in_discarded = True
                continue
            if in_discarded and (line.startswith("Memory Configuration")
                                 or line.startswith("Linker script and memory map")):
                in_discarded = False
            if in_discarded:
                continue
            for m in _OBJ_RE.finditer(line):
                objs.add(_stem(m.group(1) or m.group(2)))
    return objs


def _stem(obj_path: str) -> str:
    base = os.path.basename(obj_path.replace("\\", "/"))
    for ext in (".obj", ".o"):
        if base.endswith(ext):
            base = base[: -len(ext)]
    for ext in (".c", ".cpp", ".cc", ".s", ".S"):
        if base.endswith(ext):
            base = base[: -len(ext)]
    return base.lower()


def source_stems(root: str) -> Iterable[str]:
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            stem, ext = os.path.splitext(f)
            if ext.lower() in (".c", ".cpp", ".cc", ".s"):
                yield stem.lower()


def is_linked(component_root: str, objects: Set[str]) -> Optional[bool]:
    """True/False if the component has sources; None for header-only components."""
    stems = set(source_stems(component_root))
    if not stems:
        return None
    return bool(stems & objects)

"""Detect vendored third-party components in a C/C++ firmware source tree.

Each detector names a "marker" file that identifies the component and a list of
regexes that pull the version out of that file. Embedded projects rarely use a
package manager, so the version string inside the vendored headers is usually
the only reliable source of truth.
"""
import os
import re
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

SKIP_DIRS = {".git", ".svn", "build", "Debug", "Release", "node_modules", "__pycache__", ".venv"}


@dataclass
class Component:
    name: str
    version: str
    supplier: str
    root: str
    license: Optional[str] = None
    purl: Optional[str] = None
    cpes: List[str] = field(default_factory=list)  # first is primary
    linked: Optional[bool] = None  # None = unknown (no map file supplied)
    linkable: bool = True  # False for SDK/package-level entries (e.g. STM32Cube package from .ioc)
    evidence: List[str] = field(default_factory=list)


@dataclass
class Detector:
    name: str
    supplier: str
    marker: str  # file name that identifies the component
    parse: Callable[[str], Optional[str]]  # file text -> version
    root_levels: int = 1  # how many dirs above the marker is the component root
    license: Optional[str] = None
    purl: Optional[str] = None  # format string with {v}
    cpe: Tuple[str, ...] = ()  # format strings with {v} (version) / {vl} (lowercase version)
    path_hint: Optional[str] = None  # substring the marker path must contain


def _define(text, name):
    m = re.search(r"#\s*define\s+" + re.escape(name) + r"\s+\(?\s*([^\s)/]+)", text)
    return m.group(1).strip('"').rstrip("UuLl") if m else None


def _join_defines(*names, prefix=""):
    def parse(text):
        parts = [_define(text, n) for n in names]
        if any(p is None for p in parts):
            return None
        return prefix + ".".join(str(int(p, 0)) for p in parts)
    return parse


def _string_define(name, strip_prefix=""):
    def parse(text):
        v = _define(text, name)
        if v and strip_prefix and v.startswith(strip_prefix):
            v = v[len(strip_prefix):]
        return v
    return parse


def _regex(pattern):
    def parse(text):
        m = re.search(pattern, text)
        return m.group(1) if m else None
    return parse


def _littlefs(text):
    v = _define(text, "LFS_VERSION")
    if not v:
        return None
    n = int(v, 0)
    return "{}.{}".format(n >> 16, n & 0xFFFF)


def _mcuboot(text):
    parts = [re.search(r"^%s\s*=\s*(\d+)" % k, text, re.M) for k in ("VERSION_MAJOR", "VERSION_MINOR", "PATCHLEVEL")]
    if not all(parts):
        return None
    v = ".".join(m.group(1) for m in parts)
    extra = re.search(r"^EXTRAVERSION[ \t]*=[ \t]*(\S+)", text, re.M)
    return v + ("-" + extra.group(1) if extra else "")


def _st_release_notes(text):
    # ST release notes list the newest version first, e.g. "V2.11.6"
    m = re.search(r"\bV(\d+\.\d+\.\d+)\b", text)
    return m.group(1) if m else None


def _stm32_hal(text):
    m = re.search(r"#\s*define\s+__(STM32\w+?)_HAL_VERSION_MAIN\s+\(?\s*(0x[0-9A-Fa-f]+|\d+)", text)
    if not m:
        return None
    family = m.group(1)
    parts = []
    for part in ("MAIN", "SUB1", "SUB2"):
        v = _define(text, "__{}_HAL_VERSION_{}".format(family, part))
        if v is None:
            return None
        parts.append(str(int(v, 0)))
    return "{}:{}".format(family, ".".join(parts))


# NVD files older Mbed TLS CVEs under arm, newer ones under trustedfirmware.
_MBEDTLS_CPES = ("cpe:2.3:a:arm:mbed_tls:{v}:*:*:*:*:*:*:*",
                 "cpe:2.3:a:trustedfirmware:mbed_tls:{v}:*:*:*:*:*:*:*")

DETECTORS = [
    Detector("FreeRTOS-Kernel", "Amazon / FreeRTOS", "task.h",
             _string_define("tskKERNEL_VERSION_NUMBER", "V"),
             root_levels=2, license="MIT",
             purl="pkg:github/FreeRTOS/FreeRTOS-Kernel@V{v}", cpe=("cpe:2.3:o:amazon:freertos:{v}:*:*:*:*:*:*:*",)),
    Detector("Mbed TLS", "Arm / TrustedFirmware.org", "build_info.h",
             _string_define("MBEDTLS_VERSION_STRING"),
             root_levels=3, license="Apache-2.0 OR GPL-2.0-or-later",
             purl="pkg:github/Mbed-TLS/mbedtls@v{v}", cpe=_MBEDTLS_CPES,
             path_hint="mbedtls"),
    Detector("Mbed TLS", "Arm / TrustedFirmware.org", "version.h",  # Mbed TLS 2.x
             _string_define("MBEDTLS_VERSION_STRING"),
             root_levels=3, license="Apache-2.0",
             purl="pkg:github/Mbed-TLS/mbedtls@v{v}", cpe=_MBEDTLS_CPES,
             path_hint="mbedtls"),
    Detector("lwIP", "lwIP project", "init.h",
             _join_defines("LWIP_VERSION_MAJOR", "LWIP_VERSION_MINOR", "LWIP_VERSION_REVISION"),
             root_levels=4, license="BSD-3-Clause",
             purl="pkg:generic/lwip@{v}", cpe=("cpe:2.3:a:lwip_project:lwip:{v}:*:*:*:*:*:*:*",),
             path_hint="lwip"),
    Detector("FatFs", "ChaN", "ff.h", _regex(r"FatFs[^\n]*?\b(R\d+\.\d+[a-z]?)"),
             root_levels=1, license="FatFs (BSD-1-Clause-style)",
             purl="pkg:generic/fatfs@{v}", cpe=("cpe:2.3:a:elm-chan:fatfs:{vl}:*:*:*:*:*:*:*",)),
    Detector("littlefs", "littlefs-project", "lfs.h", _littlefs,
             root_levels=1, license="BSD-3-Clause",
             purl="pkg:github/littlefs-project/littlefs@v{v}"),
    Detector("wolfSSL", "wolfSSL Inc.", "version.h", _string_define("LIBWOLFSSL_VERSION_STRING"),
             root_levels=2, license="GPL-2.0-or-later OR commercial",
             purl="pkg:github/wolfSSL/wolfssl@v{v}-stable", cpe=("cpe:2.3:a:wolfssl:wolfssl:{v}:*:*:*:*:*:*:*",),
             path_hint="wolfssl"),
    Detector("TinyUSB", "hathach / TinyUSB", "tusb_option.h",
             _join_defines("TUSB_VERSION_MAJOR", "TUSB_VERSION_MINOR", "TUSB_VERSION_REVISION"),
             root_levels=2, license="MIT",
             purl="pkg:github/hathach/tinyusb@{v}"),
    Detector("cJSON", "Dave Gamble", "cJSON.h",
             _join_defines("CJSON_VERSION_MAJOR", "CJSON_VERSION_MINOR", "CJSON_VERSION_PATCH"),
             root_levels=1, license="MIT",
             purl="pkg:github/DaveGamble/cJSON@v{v}", cpe=("cpe:2.3:a:cjson_project:cjson:{v}:*:*:*:*:*:*:*",
                                                  "cpe:2.3:a:davegamble:cjson:{v}:*:*:*:*:*:*:*")),
    Detector("nanopb", "Petteri Aimonen", "pb.h", _regex(r"#define\s+NANOPB_VERSION\s+\"?nanopb-([\w.\-]+)\"?"),
             root_levels=1, license="Zlib",
             purl="pkg:github/nanopb/nanopb@{v}", cpe=("cpe:2.3:a:nanopb_project:nanopb:{v}:*:*:*:*:*:*:*",)),
    Detector("CMSIS-Core", "Arm", "cmsis_version.h",
             _join_defines("__CM_CMSIS_VERSION_MAIN", "__CM_CMSIS_VERSION_SUB"),
             root_levels=2, license="Apache-2.0",
             purl="pkg:github/ARM-software/CMSIS_5@{v}"),
    Detector("FreeRTOS-Plus-TCP", "Amazon / FreeRTOS", "FreeRTOS_IP.h",
             _string_define("ipFR_TCP_VERSION_NUMBER", "V"),
             root_levels=3, license="MIT",
             purl="pkg:github/FreeRTOS/FreeRTOS-Plus-TCP@V{v}",
             cpe=("cpe:2.3:a:amazon:freertos-plus-tcp:{v}:*:*:*:*:*:*:*",)),
    Detector("coreMQTT", "Amazon / FreeRTOS", "core_mqtt.h",
             _string_define("MQTT_LIBRARY_VERSION", "v"),
             root_levels=3, license="MIT",
             purl="pkg:github/FreeRTOS/coreMQTT@v{v}"),
    Detector("Eclipse ThreadX", "Eclipse Foundation (formerly Azure RTOS)", "tx_api.h",
             _join_defines("THREADX_MAJOR_VERSION", "THREADX_MINOR_VERSION", "THREADX_PATCH_VERSION"),
             root_levels=3, license="MIT",
             purl="pkg:github/eclipse-threadx/threadx@v{v}",
             cpe=("cpe:2.3:a:eclipse:threadx:{v}:*:*:*:*:*:*:*",
                  "cpe:2.3:o:microsoft:azure_rtos_threadx:{v}:*:*:*:*:*:*:*")),
    Detector("Eclipse ThreadX NetX Duo", "Eclipse Foundation (formerly Azure RTOS)", "nx_api.h",
             _join_defines("NETXDUO_MAJOR_VERSION", "NETXDUO_MINOR_VERSION", "NETXDUO_PATCH_VERSION"),
             root_levels=3, license="MIT",
             purl="pkg:github/eclipse-threadx/netxduo@v{v}",
             cpe=("cpe:2.3:a:eclipse:threadx_netx_duo:{v}:*:*:*:*:*:*:*",
                  "cpe:2.3:o:microsoft:azure_rtos_netx_duo:{v}:*:*:*:*:*:*:*")),
    Detector("MCUboot", "MCUboot project (Linaro)", "VERSION", _mcuboot,
             root_levels=3, license="Apache-2.0",
             purl="pkg:github/mcu-tools/mcuboot@v{v}", path_hint="mcuboot"),
    Detector("STM32 USB Device Library", "STMicroelectronics", "Release_Notes.html", _st_release_notes,
             root_levels=1, license="SLA0044 / Apache-2.0 (see package)",
             purl="pkg:github/STMicroelectronics/stm32-mw-usb-device@v{v}", path_hint="usb_device"),
    Detector("STM32 USB Device Library", "STMicroelectronics", "Release_Notes.html", _st_release_notes,
             root_levels=1, license="SLA0044 / Apache-2.0 (see package)",
             purl="pkg:github/STMicroelectronics/stm32-mw-usb-device@v{v}", path_hint="usb-device"),
    Detector("STM32 USB Host Library", "STMicroelectronics", "Release_Notes.html", _st_release_notes,
             root_levels=1, license="SLA0044 / Apache-2.0 (see package)",
             purl="pkg:github/STMicroelectronics/stm32-mw-usb-host@v{v}", path_hint="usb_host"),
    Detector("STM32 USB Host Library", "STMicroelectronics", "Release_Notes.html", _st_release_notes,
             root_levels=1, license="SLA0044 / Apache-2.0 (see package)",
             purl="pkg:github/STMicroelectronics/stm32-mw-usb-host@v{v}", path_hint="usb-host"),
]


def _cube_package_from_ioc(text):
    """STM32CubeMX .ioc: 'ProjectManager.FirmwarePackage=STM32Cube FW_L4 V1.18.1' -> ('STM32Cube FW_L4', '1.18.1')."""
    m = re.search(r"^ProjectManager\.FirmwarePackage=(STM32Cube FW_\w+) V(\d+\.\d+\.\d+)", text, re.M)
    return (m.group(1), m.group(2)) if m else None


def _stm32_hal_detectors():
    # HAL version lives in e.g. Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal.c
    return Detector("STM32Cube HAL", "STMicroelectronics", "", _stm32_hal,
                    root_levels=2, license="BSD-3-Clause")


def _iter_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for f in filenames:
            yield dirpath, f


def _read(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(200_000)
    except OSError:
        return ""


def _up(path, levels):
    for _ in range(levels):
        path = os.path.dirname(path)
    return path


def detect(root: str) -> List[Component]:
    by_marker = {}
    for d in DETECTORS:
        by_marker.setdefault(d.marker, []).append(d)
    hal = _stm32_hal_detectors()
    hal_re = re.compile(r"^stm32\w+_hal\.c$", re.IGNORECASE)

    found = {}
    for dirpath, fname in _iter_files(root):
        path = os.path.join(dirpath, fname)
        candidates = list(by_marker.get(fname, []))
        if hal_re.match(fname):
            candidates.append(hal)
        if fname.lower().endswith(".ioc"):
            pkg = _cube_package_from_ioc(_read(os.path.join(dirpath, fname)))
            if pkg:
                family = pkg[0].split("_", 1)[1]  # e.g. "L4"
                key = (pkg[0], pkg[1], os.path.normpath(dirpath))
                found.setdefault(key, Component(
                    name=pkg[0], version=pkg[1], supplier="STMicroelectronics", root=os.path.normpath(dirpath),
                    license="See package", purl="pkg:github/STMicroelectronics/STM32Cube{}@v{}".format(family, pkg[1]),
                    linkable=False,
                    evidence=[os.path.relpath(os.path.join(dirpath, fname), root).replace("\\", "/")]))
            continue
        if not candidates:
            continue
        text = None
        for d in candidates:
            if d.path_hint and d.path_hint not in path.replace("\\", "/").lower():
                continue
            if text is None:
                text = _read(path)
            version = d.parse(text)
            if not version:
                continue
            name = d.name
            if d is hal:
                family, version = version.split(":", 1)
                name = "{} HAL Driver".format(family)
            comp_root = os.path.normpath(_up(path, d.root_levels))
            key = (name, version, comp_root)
            if key in found:
                continue
            found[key] = Component(
                name=name, version=version, supplier=d.supplier, root=comp_root,
                license=d.license,
                purl=d.purl.format(v=version) if d.purl else
                "pkg:generic/{}@{}".format(name.lower().replace(" ", "-"), version),
                cpes=[c.format(v=version, vl=version.lower()) for c in d.cpe],
                evidence=[os.path.relpath(path, root).replace("\\", "/")],
            )
            break
    # A component nested inside another copy of itself (e.g. packaging mirrors) is one component.
    comps = sorted(found.values(), key=lambda c: len(c.root))
    kept = []
    for c in comps:
        if not any(k.name == c.name and k.version == c.version
                   and os.path.commonpath([k.root, c.root]) == k.root for k in kept):
            kept.append(c)
    return sorted(kept, key=lambda c: (c.name.lower(), c.version))

import json
import os
import tempfile
import unittest

from fwsbom import cli, detectors, mapfile

FILES = {
    "Middlewares/FreeRTOS-Kernel/include/task.h": '#define tskKERNEL_VERSION_NUMBER "V10.6.2"\n',
    "Middlewares/FreeRTOS-Kernel/tasks.c": "",
    "Middlewares/FreeRTOS-Kernel/queue.c": "",
    "Middlewares/mbedtls/include/mbedtls/build_info.h": '#define MBEDTLS_VERSION_STRING         "3.6.2"\n',
    "Middlewares/mbedtls/library/ssl_tls.c": "",
    "Middlewares/lwip/src/include/lwip/init.h":
        "#define LWIP_VERSION_MAJOR      2\n#define LWIP_VERSION_MINOR      1\n#define LWIP_VERSION_REVISION   3\n",
    "Middlewares/lwip/src/core/tcp.c": "",
    "Middlewares/FatFs/ff.h": "/  FatFs - Generic FAT Filesystem module  R0.15                                 /\n",
    "Middlewares/FatFs/ff.c": "",
    "Middlewares/littlefs/lfs.h": "#define LFS_VERSION 0x00020009\n",
    "Middlewares/littlefs/lfs.c": "",
    "Drivers/CMSIS/Core/Include/cmsis_version.h":
        "#define __CM_CMSIS_VERSION_MAIN  ( 5U)\n#define __CM_CMSIS_VERSION_SUB   ( 6U)\n",
    "Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal.c":
        "#define __STM32F4xx_HAL_VERSION_MAIN   (0x01U)\n"
        "#define __STM32F4xx_HAL_VERSION_SUB1   (0x08U)\n"
        "#define __STM32F4xx_HAL_VERSION_SUB2   (0x03U)\n",
    "Core/Src/main.c": "",
    "Middlewares/Third_Party/FreeRTOS-Plus-TCP/source/include/FreeRTOS_IP.h":
        '#define ipFR_TCP_VERSION_NUMBER    "V4.4.1"\n',
    "Middlewares/coreMQTT/source/include/core_mqtt.h": '#define MQTT_LIBRARY_VERSION    "v5.0.2"\n',
    "Middlewares/threadx/common/inc/tx_api.h":
        "#define THREADX_MAJOR_VERSION 6\n#define THREADX_MINOR_VERSION 5\n#define THREADX_PATCH_VERSION 2\n",
    "Middlewares/netxduo/common/inc/nx_api.h":
        "#define NETXDUO_MAJOR_VERSION 6\n#define NETXDUO_MINOR_VERSION 4\n#define NETXDUO_PATCH_VERSION 1\n",
    "Bootloader/mcuboot/boot/zephyr/VERSION":
        "VERSION_MAJOR = 2\nVERSION_MINOR = 1\nPATCHLEVEL = 0\nVERSION_TWEAK = 0\nEXTRAVERSION =\n",
    "Bootloader/mcuboot/ext/tinycrypt/VERSION": "0.2.8\n",  # must not be mistaken for MCUboot
    "Middlewares/ST/STM32_USB_Device_Library/Release_Notes.html":
        "<h2>Update history</h2><p>V2.11.3 / 07-June-2024</p><p>V2.11.2 / 2023</p>",
    "demo.ioc": "MxCube.Version=6.14.0\nProjectManager.FirmwarePackage=STM32Cube FW_F4 V1.28.1\n",
    # Unrelated version.h must not be mistaken for Mbed TLS / wolfSSL
    "Core/Inc/version.h": '#define MBEDTLS_VERSION_STRING "9.9.9"\n',
}

# littlefs and FatFs are compiled but dropped; the rest is linked.
MAP = """Archive member included to satisfy reference by file (symbol)

Discarded input sections

 .text.lfs_mount  0x00000000  0x120 build/Middlewares/littlefs/lfs.o
 .text.f_mount    0x00000000  0x80  build/Middlewares/FatFs/ff.o

Memory Configuration

Linker script and memory map

 .text          0x08000400      0x2a0 build/Core/Src/main.o
 .text          0x08000800      0x900 build/Middlewares/FreeRTOS-Kernel/tasks.o
 .text          0x08001200      0x400 build/Middlewares/lwip/src/core/tcp.c.obj
 .text          0x08002000      0x300 build/libmbedtls.a(ssl_tls.o)
 .text          0x08003000      0x100 build/Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal.o
"""


class FwsbomTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        for rel, text in FILES.items():
            path = os.path.join(self.root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write(text)
        self.map = os.path.join(self.root, "fw.map")
        with open(self.map, "w") as fh:
            fh.write(MAP)

    def tearDown(self):
        self.tmp.cleanup()

    def test_detect_versions(self):
        got = {c.name: c.version for c in detectors.detect(self.root)}
        self.assertEqual(got, {
            "FreeRTOS-Kernel": "10.6.2",
            "Mbed TLS": "3.6.2",
            "lwIP": "2.1.3",
            "FatFs": "R0.15",
            "littlefs": "2.9",
            "CMSIS-Core": "5.6",
            "STM32F4xx HAL Driver": "1.8.3",
            "FreeRTOS-Plus-TCP": "4.4.1",
            "coreMQTT": "5.0.2",
            "Eclipse ThreadX": "6.5.2",
            "Eclipse ThreadX NetX Duo": "6.4.1",
            "MCUboot": "2.1.0",
            "STM32 USB Device Library": "2.11.3",
            "STM32Cube FW_F4": "1.28.1",
        })

    def test_component_roots(self):
        roots = {c.name: os.path.relpath(c.root, self.root).replace("\\", "/") for c in detectors.detect(self.root)}
        self.assertEqual(roots["FreeRTOS-Kernel"], "Middlewares/FreeRTOS-Kernel")
        self.assertEqual(roots["Mbed TLS"], "Middlewares/mbedtls")
        self.assertEqual(roots["lwIP"], "Middlewares/lwip")
        self.assertEqual(roots["STM32F4xx HAL Driver"], "Drivers/STM32F4xx_HAL_Driver")

    def test_linkage_from_map(self):
        objs = mapfile.linked_objects(self.map)
        linked = {c.name: mapfile.is_linked(c.root, objs) for c in detectors.detect(self.root)}
        self.assertTrue(linked["FreeRTOS-Kernel"])
        self.assertTrue(linked["lwIP"])
        self.assertTrue(linked["Mbed TLS"])
        self.assertTrue(linked["STM32F4xx HAL Driver"])
        self.assertFalse(linked["littlefs"])
        self.assertFalse(linked["FatFs"])
        self.assertIsNone(linked["CMSIS-Core"])  # header-only
        comps = {c.name: c for c in detectors.detect(self.root)}
        self.assertFalse(comps["STM32Cube FW_F4"].linkable)  # SDK package from .ioc: never "linked"
        self.assertEqual(comps["STM32Cube FW_F4"].purl, "pkg:github/STMicroelectronics/STM32CubeF4@v1.28.1")
        self.assertEqual(comps["Eclipse ThreadX"].cpes[0], "cpe:2.3:a:eclipse:threadx:6.5.2:*:*:*:*:*:*:*")

    def test_cli_emits_cyclonedx(self):
        out = os.path.join(self.root, "sbom.json")
        cli.main([self.root, "--map", self.map, "--linked-only", "--name", "demo",
                  "--version", "1.2.0", "--supplier", "Acme", "-o", out])
        with open(out) as fh:
            bom = json.load(fh)
        self.assertEqual(bom["bomFormat"], "CycloneDX")
        self.assertEqual(bom["metadata"]["component"]["name"], "demo")
        names = {c["name"] for c in bom["components"]}
        self.assertNotIn("littlefs", names)
        self.assertNotIn("FatFs", names)
        self.assertIn("CMSIS-Core", names)
        mbed = next(c for c in bom["components"] if c["name"] == "Mbed TLS")
        self.assertEqual(mbed["cpe"], "cpe:2.3:a:arm:mbed_tls:3.6.2:*:*:*:*:*:*:*")
        self.assertEqual(mbed["purl"], "pkg:github/Mbed-TLS/mbedtls@v3.6.2")
        self.assertIn({"name": "syft:cpe23", "value": "cpe:2.3:a:trustedfirmware:mbed_tls:3.6.2:*:*:*:*:*:*:*"},
                      mbed["properties"])
        rtos = next(c for c in bom["components"] if c["name"] == "FreeRTOS-Kernel")
        self.assertEqual(rtos["cpe"], "cpe:2.3:o:amazon:freertos:10.6.2:*:*:*:*:*:*:*")
        refs = {c["bom-ref"] for c in bom["components"]}
        self.assertEqual(set(bom["dependencies"][0]["dependsOn"]), refs)

    def test_fatfs_cpe_lowercase(self):
        fatfs = next(c for c in detectors.detect(self.root) if c.name == "FatFs")
        self.assertEqual(fatfs.cpes, ["cpe:2.3:a:elm-chan:fatfs:r0.15:*:*:*:*:*:*:*"])


if __name__ == "__main__":
    unittest.main()

# fwsbom

**SBOMs for bare-metal and RTOS firmware: the projects other SBOM tools miss.**

Syft, Trivy and most SBOM generators look for package-manager lockfiles. A typical
STM32 / NXP / Nordic / ESP firmware project has none. Its third-party code is vendored
straight into the tree (FreeRTOS, Mbed TLS, lwIP, FatFs, HAL drivers), and
`--gc-sections` decides what actually ships. The result is SBOMs that are empty or wrong.

`fwsbom` reads the version numbers out of the vendored sources themselves. It then
checks your **linker map file** to report only what really made it into the image.

```
$ fwsbom . --map build/app.map --linked-only --name gateway --version 2.4.1 \
         --supplier "Acme Devices" -o sbom.cdx.json
COMPONENT                    VERSION        LINKED  EVIDENCE
CMSIS-Core                   5.6            ?       Drivers/CMSIS/Core/Include/cmsis_version.h
FreeRTOS-Kernel              10.6.2         yes     Middlewares/FreeRTOS-Kernel/include/task.h
lwIP                         2.1.3          yes     Middlewares/lwip/src/include/lwip/init.h
Mbed TLS                     3.6.2          yes     Middlewares/mbedtls/include/mbedtls/build_info.h
STM32F4xx HAL Driver         1.8.3          yes     Drivers/STM32F4xx_HAL_Driver/Src/stm32f4xx_hal.c
5 component(s)
```

The output is CycloneDX 1.5 JSON. Each component carries a purl, and a CPE where NVD
has one, so the SBOM can be fed straight into Dependency-Track, OSV-Scanner or Grype
for vulnerability monitoring:

```
$ fwsbom . -o sbom.cdx.json && grype sbom:sbom.cdx.json
```

CPEs are checked against the NVD product dictionary. Products filed under several vendors
(e.g. Mbed TLS: `arm` and `trustedfirmware`) get all of their CPEs, so matches are not lost to vendor naming.

## Install

```
pip install fwsbom
```

Requires Python 3.9+ and has no dependencies.

**Windows:** if `fwsbom` is "not recognized" after installing (common with the Microsoft Store Python,
whose scripts folder isn't on PATH), run it as **`python -m fwsbom ...`**. It's the same tool.
Install Grype with **`winget install Anchore.Grype`**, then open a new terminal.

## Detected components

**RTOS:** FreeRTOS-Kernel · Eclipse ThreadX (Azure RTOS)
**Networking / IoT:** lwIP · FreeRTOS-Plus-TCP · NetX Duo · coreMQTT · Mbed TLS (2.x/3.x/4.x) · wolfSSL
**Boot:** MCUboot
**USB:** TinyUSB · STM32 USB Device / Host libraries
**Storage / data:** FatFs · littlefs · cJSON · nanopb
**Vendor:** CMSIS-Core · STM32Cube HAL drivers (all families) · **STM32Cube firmware package version from
the CubeMX `.ioc` file** (e.g. `STM32Cube FW_L4 1.18.1`)

The `LINKED` column means:
- `yes`: at least one of the component's sources ended up in the image
- `no`: compiled or vendored, but nothing reached the image (dropped with `--linked-only`)
- `?`: the component is header-only, or no map file was given

Missing a library you use? Open an issue. Adding a detector takes about 5 lines.

## Why this matters now: EU Cyber Resilience Act

- **Since 11 Sep 2026**, manufacturers of products with digital elements sold in the EU
  must report actively exploited vulnerabilities to ENISA within **24 hours**. Without a
  component inventory you cannot tell whether a new CVE affects you in time.
- **From 11 Dec 2027**, a machine-readable SBOM is part of the mandatory technical documentation.
- Penalties reach €15M or 2.5% of global turnover.

## Need help getting CRA-ready?

`fwsbom` is free and Apache-2.0. Chen Embedded Software LLC also offers:

- **CRA Firmware Readiness Kit**: policy templates, vulnerability-handling process,
  ENISA report templates and a CI pipeline that regenerates and monitors your SBOM.
- **Firmware CRA assessment** (waitlist): a fixed-price review of your firmware, secure boot,
  update mechanism and SBOM, with a prioritised gap report.

Contact: **chenembeddedsoftware@gmail.com** (or open an issue for bugs and feature requests)

## License

Apache-2.0 © 2026 Chen Embedded Software LLC

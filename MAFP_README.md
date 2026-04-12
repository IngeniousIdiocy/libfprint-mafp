# libfprint-mafp: Open-Source Linux Driver for Microarray MAFP8800 Fingerprint Sensor

## Why this exists

The Microarray MAFP8800 is an SPI fingerprint sensor found in devices like the **GPD MicroPC 2**. It works out of the box on Windows, but has **zero Linux support** — no mainline kernel driver, no libfprint driver, no AUR package, nothing on GitHub.

The only Linux driver that exists is a **closed-source binary** distributed informally on the [GPD Devices Discord](https://discord.com/invite/FzEsh3k). It ships as:
- A pre-compiled kernel module (`madev.ko`) built for a specific kernel version
- A binary-only patched `libfprint-2.so` (no source code) packaged as a `.deb` for Ubuntu 24.10 only

**This is a security problem.** A fingerprint driver has privileged access to biometric data and runs as root. Distributing it as an unverifiable binary through Discord — with no code review, no reproducible build, no signature — means users must blindly trust that the binary is what it claims to be. It could contain anything.

This project provides a **fully open-source replacement** that:
- Has every line of code visible and auditable
- Builds from source on any Linux distribution with libfprint
- Documents the complete sensor protocol so others can verify and improve it
- Can be submitted upstream to [libfprint](https://gitlab.freedesktop.org/libfprint/libfprint) for inclusion in every distro's package manager

## Current status

**Working:**
- Sensor detection and identification (FP36 variant, chip ID 0x24)
- Hardware calibration (binary-search gain optimization, 3-pass detection threshold calibration)
- Calibration persistence (`/var/lib/fprint/mafp_calibration`)
- Finger detection with hysteresis (31% pixel threshold, directional comparison)
- Finger stability checking (sum-of-absolute-differences)
- Image capture (160×37 pixels, 16-bit raw, cmd 0x70)
- Image enhancement (background subtraction, min-max normalization)
- Fingerprint enrollment (8 stages via fprintd)
- Detection mode register configuration (15 registers, calibrated thresholds)
- udev auto-binding (spidev driver_override on ACPI match)
- Worker thread architecture (non-blocking fprintd integration)

**In progress:**
- Fingerprint matching reliability — NCC pixel correlation works but needs threshold tuning for consistent same-finger acceptance while rejecting different fingers. The community driver uses a proprietary EPVM feature extraction algorithm; we're evaluating open alternatives.

**Not yet implemented:**
- FP88 variant support (chip ID 0x58, different image geometry)
- PAM integration testing
- Suspend/resume handling
- Upstream submission to libfprint

## Supported hardware

| Device | Sensor | Chip ID | Interface | Status |
|--------|--------|---------|-----------|--------|
| GPD MicroPC 2 | Microarray MAFP8800 (FP36) | 0x24 | SPI (ACPI HID `MAFP8800`) | Working |
| Other MAFP8800 devices | Microarray MAFP8800 (FP88) | 0x58 | SPI | Detected, not supported |

## Building

This is a fork of [libfprint v1.94.7](https://gitlab.freedesktop.org/libfprint/libfprint) with the `mafp` driver added.

### Prerequisites

```bash
sudo apt install -y meson ninja-build libfprint-2-dev libglib2.0-dev \
  libgusb-dev libnss3-dev libgudev-1.0-dev libpixman-1-dev \
  gobject-introspection libgirepository1.0-dev
```

### Build and install

```bash
git clone https://github.com/IngeniousIdiocy/libfprint-mafp.git
cd libfprint-mafp
meson setup builddir -Ddoc=false -Dgtk-examples=false
ninja -C builddir
sudo ninja -C builddir install
sudo ldconfig
```

### System configuration

**Udev rule** — auto-bind spidev to the sensor on boot:

```bash
sudo tee /etc/udev/rules.d/70-mafp-spidev.rules << 'EOF'
ACTION=="add|change", SUBSYSTEM=="spi", ENV{MODALIAS}=="acpi:MAFP8800:", \
  RUN{builtin}+="kmod load spi:spidev", \
  RUN+="/bin/sh -c 'echo spidev > %S%p/driver_override && echo %k > %S%p/subsystem/drivers/spidev/bind'"
ACTION=="add", KERNEL=="spidev*", SUBSYSTEM=="spidev", MODE="0660", GROUP="plugdev"
EOF
sudo udevadm control --reload-rules
```

**spidev buffer size** — the sensor needs 20 KB transfers:

```bash
echo 'options spidev bufsiz=32768' | sudo tee /etc/modprobe.d/spidev-bufsiz.conf
```

### Testing

```bash
sudo systemctl restart fprintd
fprintd-list $USER                    # Should show "Microarray MAFP Fingerprint Sensor"
sudo fprintd-enroll -f right-index-finger   # Enroll (8 stages)
sudo fprintd-verify                         # Verify
```

## Protocol documentation

The sensor uses a simple register-level SPI protocol (match-on-host mode). All communication is via 4-byte full-duplex SPI transfers:

- **TX:** `[register, value, 0x00, 0x00]`
- **Response:** byte at position 2 of the RX buffer

### Key registers

| Register | Purpose | Values |
|----------|---------|--------|
| 0x00 | Status | Read: 0x41 = ready |
| 0x04 | Chip ID | 0x24 = FP36, 0x58 = FP88 |
| 0x0E | Manufacturer | 0x4D = 'M' (Microarray) |
| 0x8C | Reset trigger | Write 0xFF to reset |
| 0x88 | Capture mode | Write 0xFF to enter |
| 0x10-0x5C | Configuration | Gain, timing, thresholds |
| 0x84 | Detection arm | Write 0x00 to arm |

### Image capture

1. Reset: write reg 0x8C = 0xFF, poll reg 0x04 until == 0x24
2. Configure: write capture mode registers (0x20, 0x18, 0x38, 0x40, 0x48, 0x3C, 0x44)
3. Flush: SPI read 0x26 bytes with cmd 0x78
4. Read image: SPI transfer 20480 bytes with cmd 0x70
5. Parse: scan for row markers `[0x00, 0x00, 0x0A, 0x5X]`, extract 74-byte rows
6. Decode: 37 big-endian 16-bit pixels per row, 160 rows

Full protocol documentation is in `docs/PROTOCOL.md` (in the mafp-linux workspace).

## Architecture

The driver is a single C file (`libfprint/drivers/mafp.c`) that:

- Subclasses `FpDevice` directly (not `FpImageDevice`) — matches the community driver's architecture
- Runs all SPI operations in a dedicated worker thread via GCond/GMutex signaling
- Stores fingerprint templates as 8-bit pixel data in `FPI_PRINT_RAW` GVariant format
- Uses normalized cross-correlation (NCC) with ±20 row vertical translation search for matching

### Why not FpImageDevice?

libfprint's `FpImageDevice` base class runs NBIS minutiae extraction (mindtct + bozorth3) on captured images. NBIS requires ~500 DPI images with clear ridge/valley patterns. The MAFP8800's 36×160 pixel sensor at ~200 DPI doesn't produce enough detail for reliable NBIS minutiae detection (typically finds 0-5 minutiae, far too few for bozorth matching).

The community driver solves this with a custom EPVM (Embedded Pattern-Vector Matching) algorithm that extracts 2012-byte feature descriptors tuned for low-resolution sensors. Our driver currently uses NCC pixel correlation as an intermediate solution while we evaluate open-source alternatives to EPVM.

## Project history

This driver was built through multi-session reverse engineering of the Windows `MafpWinbioDriver.dll` and the community Linux binary. Key milestones:

1. **Protocol discovery** — decoded the Spi2spi/Syno protocol from the Windows driver (turned out to be unused by this chip variant)
2. **First light** — discovered the chip uses simple register-level SPI, not the complex Spi2spi framing
3. **Community driver analysis** — found the Discord-distributed binary, decoded its complete protocol from debug symbols
4. **Driver implementation** — built the libfprint driver matching the community driver's exact register sequences and calibration algorithm

## Contributing

This is an active project. Areas where help is needed:

- **Matching algorithm** — improving NCC or implementing an open-source alternative to EPVM for low-resolution sensors
- **FP88 variant** — supporting chips with ID 0x58 (different image geometry, already partially decoded)
- **Testing on other devices** — the MAFP8800 may appear in devices beyond the GPD MicroPC 2
- **Upstream submission** — preparing the driver for a libfprint merge request

## License

LGPL-2.1-or-later (matching libfprint's license).

The driver code is original work based on protocol analysis. No proprietary code was copied from the community binary or the Windows driver.

# NXINF

A small Windows console tool that dumps hardware and system identifiers in one shot — the kind of stuff you'd otherwise gather by running half a dozen `wmic`/PowerShell commands by hand.

```
   _   ___  _____ _   _ _____
  | \ | \ \/ /_ _| \ | |  ___|
  |  \| |\  / | ||  \| | |_
  | |\  |/  \ | || |\  |  _|
  |_| \_/_/\_\___|_| \_|_|
  Hardware & System Identification Console
```

[![VirusTotal](https://img.shields.io/badge/VirusTotal-4%2F71%20clean-brightgreen?logo=virustotal&logoColor=white)](https://www.virustotal.com/gui/file/00bfbcbf492109ebf9eb514906ffac1c500d0c1229264511035f5c84976ca1a4)

## What it shows

| Section | What you get |
|---|---|
| Disk / SSD | Physical drive serial numbers |
| Volumes | Per-volume `VolumeSerialNumber` |
| SMBIOS | Motherboard UUID, BIOS serial, chassis serial |
| MAC Address(es) | Every network adapter's MAC (physical + virtual) |
| CPU / GPU | Processor ID, GPU device path |
| TPM | Presence/state + EK (Endorsement Key) MD5/SHA1/SHA256 when the TPM exposes one |
| Memory / RAM | Per-stick serial number |
| Windows Product Key | Firmware-embedded OEM key if present, legacy registry decode as a clearly-labeled fallback |

## Why this exists

Needed a single tool to pull every identifier a licensing system, anti-cheat, or asset-tracking script might check, instead of re-typing the same WMI queries every time. Some of these turned out to be a lot more nuanced to get *right* than to get *some output for* — see "A couple of honest caveats" below, it matters.

The source is included in the repo for transparency — it's just Python, no obfuscation — but the intended way to actually run this is the prebuilt `.exe` from Releases.

## Requirements

- Windows 10/11
- That's it — the release is a standalone `.exe`, nothing else to install.

## Usage

1. Grab `NXINF.exe` from the [Releases](../../releases) page.
2. Right-click it → **Run as administrator**.
3. Read.

Running without elevation isn't going to crash anything, but Windows will quietly withhold some of the deeper stuff (TPM details and the firmware product key mainly) from a non-admin process, so those sections will just come back empty. That's Windows' own permission model at work, not the tool being broken.

Windows Defender / SmartScreen may flag the executable on first run — that's standard for any unsigned binary that reads system-level internals like this one does, not a sign anything's actually wrong with it. The source (`nxinf.py`) is right here in the repo if you want to check exactly what it does before running it, or build it yourself.

## A couple of honest caveats

**TPM hashes aren't always available, and that's not a bug.** `Get-TpmEndorsementKeyInfo` (the official PowerShell cmdlet) only supports SHA256 — that's a Microsoft limitation, not something this script chose. To get MD5/SHA1 too, NXINF pulls the raw EK public key bytes and hashes them itself in Python. But some TPMs — firmware TPMs especially (AMD fTPM, Intel PTT), which is most modern CPUs — simply don't ship with an exportable EK certificate or public key at all. If section 6 comes back empty on your machine, that's very likely just what your hardware has to offer, not a script failure.

**The Windows product key section prioritizes trust over always-showing-something.** There are two very different ways to get a product key:

1. `OA3xOriginalProductKey` — the OEM key burned into UEFI/BIOS firmware at the factory. If present, genuine, full stop. Mostly a "prebuilt laptop from a major manufacturer" thing.
2. The classic `DigitalProductId` registry decode (the algorithm every "get my Windows key" tutorial has used since Windows 7). **This one always produces a correctly-formatted 25-character key, whether or not it's real.** On any modern install using a digital license (activated via Microsoft account or hardware hash, no stored key at all — increasingly the default on Windows 10/11), this method will confidently hand you a plausible-looking key that was never actually used to activate anything.

NXINF tries method 1 first and only falls back to method 2 if that's empty — and when it does fall back, it labels the result `LOW TRUST / UNVERIFIED` rather than presenting it with the same confidence as a real firmware key. If you see that warning, don't use the key to reactivate or reinstall anything without checking it some other way first.

## A word on what this actually does

This reads hardware and system identifiers that are also exactly the kind of data used for machine fingerprinting — by license servers, anti-cheat systems, EDR/security tooling, and so on. There's nothing wrong with reading this off your own machine for diagnostics, inventory, or curiosity. Just know what you're looking at, and don't run this against a machine that isn't yours without a good reason to.

## License

MIT — do what you want with it, no warranty implied. See [LICENSE](LICENSE).

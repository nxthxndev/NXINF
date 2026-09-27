"""
NXINF - Hardware & System Identification Console
==================================================

Pulls together the usual suspects for hardware/system fingerprinting on
Windows: disk serials, SMBIOS, MAC addresses, CPU/GPU IDs, TPM endorsement
key hashes, RAM serials, and the Windows product key (when one actually
exists to find).

Started this because I needed a quick way to dump all the identifiers a
license server / anti-cheat / whatever might check, in one shot, instead of
running ten different wmic commands by hand every time. Turned out some of
these (TPM hashes especially) are a lot messier to get right than I expected -
see the comments in get_tpm_ek_hashes() if you're curious why.

Needs Windows (uses WMI via PowerShell + certutil). Run as admin or a couple
of sections will come back empty - Windows just won't hand over that stuff
to a non-elevated process.

    python nxinf.py
"""

import subprocess
import sys
import os
import ctypes
import platform
import hashlib
import tempfile


# =========================================================================
#  Console colors
# =========================================================================
# Nothing fancy, just raw ANSI codes. Didn't want to pull in a dependency
# (colorama etc.) for something this small - Windows 10/11 terminals handle
# ANSI fine once you flip the console mode flag below, so no need.

class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    CYAN = "\033[38;5;51m"
    MAGENTA = "\033[38;5;201m"
    GREEN = "\033[38;5;83m"
    YELLOW = "\033[38;5;220m"
    RED = "\033[38;5;203m"
    BLUE = "\033[38;5;75m"
    GRAY = "\033[38;5;244m"
    WHITE = "\033[38;5;255m"
    ORANGE = "\033[38;5;208m"


def _enable_ansi_on_windows():
    # Old-school cmd.exe ignores ANSI codes unless you explicitly ask for
    # them via SetConsoleMode. Windows Terminal / PowerShell 7 don't need
    # this but it doesn't hurt to call it anyway - just silently no-ops if
    # it fails for whatever reason (e.g. running inside some weird pipe).
    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        kernel32.GetConsoleMode(handle, ctypes.byref(mode))
        kernel32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except Exception:
        pass


def banner():
    art = f"""{C.CYAN}{C.BOLD}
   _   ___  _____ _   _ _____
  | \\ | \\ \\/ /_ _| \\ | |  ___|
  |  \\| |\\  / | ||  \\| | |_
  | |\\  |/  \\ | || |\\  |  _|
  |_| \\_/_/\\_\\___|_| \\_|_|
{C.RESET}{C.GRAY}  Hardware & System Identification Console{C.RESET}
{C.DIM}  ---------------------------------------------------{C.RESET}
"""
    print(art)


def section(title: str, icon: str = "»"):
    print()
    print(f"{C.MAGENTA}{C.BOLD}┌{'─' * 68}┐{C.RESET}")
    print(f"{C.MAGENTA}{C.BOLD}│ {C.CYAN}{icon} {title}{C.RESET}")
    print(f"{C.MAGENTA}{C.BOLD}└{'─' * 68}┘{C.RESET}")


def kv(label: str, value: str, color: str = C.GREEN, indent: int = 2):
    pad = " " * indent
    print(f"{pad}{C.GRAY}{label}:{C.RESET} {color}{value}{C.RESET}")


def raw(text: str):
    print(f"{C.WHITE}{text}{C.RESET}")


def warn(text: str):
    print(f"{C.YELLOW}{C.BOLD}⚠ {text}{C.RESET}")


def error(text: str):
    print(f"{C.RED}{C.BOLD}✗ {text}{C.RESET}")


def ok(text: str):
    print(f"{C.GREEN}✓ {text}{C.RESET}")


def info(text: str):
    print(f"{C.BLUE}ℹ {text}{C.RESET}")


# =========================================================================
#  Shelling out to PowerShell / cmd
# =========================================================================
# Everything here goes through subprocess rather than a proper WMI binding
# (pywin32, wmi package, etc.) on purpose - keeps this to stdlib only so
# anyone can just run the script without pip installing anything first.
# The tradeoff is we're parsing text output instead of real objects, which
# is a bit fragile but Format-Table/Out-String keeps it predictable enough.

def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        # Not on Windows, or the call itself failed - either way, assume no.
        return False


def run_ps(command: str, timeout: int = 30) -> str:
    """Run a PowerShell command and hand back whatever it printed."""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = result.stdout.strip()
        if not output and result.stderr.strip():
            return f"(PowerShell error: {result.stderr.strip()[:300]})"
        return output if output else "(empty / not available)"
    except FileNotFoundError:
        return "(PowerShell not found - this script requires Windows)"
    except subprocess.TimeoutExpired:
        return "(timeout - command took too long)"
    except Exception as e:
        return f"(error: {e})"


def run_cmd(args, timeout: int = 30) -> str:
    """Same idea as run_ps but for plain executables (certutil, etc)."""
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        out = result.stdout.strip()
        if not out and result.stderr.strip():
            return f"(error: {result.stderr.strip()[:300]})"
        return out if out else "(empty / not available)"
    except FileNotFoundError:
        return f"(command not found: {args[0]})"
    except subprocess.TimeoutExpired:
        return "(timeout)"
    except Exception as e:
        return f"(error: {e})"


def hash_file(path: str) -> dict:
    """MD5/SHA1/SHA256 of a file, read in chunks so we don't choke on big ones."""
    hashes = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            for h in hashes.values():
                h.update(chunk)
    return {k: v.hexdigest() for k, v in hashes.items()}


# =========================================================================
#  [6] TPM - Endorsement Key
# =========================================================================
# This section took way longer to get right than I expected, so a bit of
# context on why it's three fallback methods deep instead of one clean call.
#
# The obvious approach is PowerShell's Get-TpmEndorsementKeyInfo cmdlet, and
# it does work - but it only supports SHA256 as a hash algorithm. That's not
# a bug on my end, it's literally the only option Microsoft's docs list for
# -HashAlgorithm. So if you want MD5/SHA1 too (some tools/services still ask
# for them), you can't just pass a different flag - you have to grab the raw
# public key bytes yourself and hash those in Python instead.
#
# On top of that, not every TPM even has an EK certificate sitting around
# to read. Discrete TPMs (Infineon, ST) usually ship with one burned in at
# the factory. Firmware TPMs - AMD fTPM, Intel PTT, the kind built into most
# modern CPUs instead of a separate chip - frequently don't. So certutil's
# -tpmekcert can legitimately come back empty, and that's not something this
# script can work around; there's just nothing there to extract.

def get_tpm_ek_hashes() -> dict:
    """
    Tries, in order:
      1. Pull the full EK certificate via certutil -tpmekcert (best case,
         gives us a real X.509 cert to hash).
      2. Ask Get-TpmEndorsementKeyInfo for the raw public key bytes and hash
         those ourselves in Python (works around the SHA256-only limitation).
      3. Fall back to whatever SHA256 Windows already computed, if the raw
         bytes weren't exposed either. No way to get MD5/SHA1 from this path.

    Returns unavailable if none of the three pan out - which does happen on
    plenty of real machines, it's not necessarily a sign anything is wrong.
    """
    tmp_dir = tempfile.mkdtemp(prefix="nxinf_tpm_")
    cert_path = os.path.join(tmp_dir, "ek.cer")
    pubkey_path = os.path.join(tmp_dir, "ek_pubkey.bin")

    # --- Method 1: the "proper" EK certificate, if the TPM shipped with one ---
    result1 = run_cmd(["certutil", "-silent", "-tpmekcert", cert_path], timeout=25)
    if os.path.exists(cert_path) and os.path.getsize(cert_path) > 0:
        try:
            return {"status": "ok", "source": "EK certificate (X.509)",
                     "path": cert_path, **hash_file(cert_path)}
        except Exception:
            pass  # weird, but let's not give up - try method 2

    # --- Method 2: raw public key bytes, hashed ourselves ---
    # WriteAllBytes needs the RawData property specifically - the PublicKey
    # object itself isn't something you can just dump to disk directly.
    ps_export = rf"""
try {{
    $ek = Get-TpmEndorsementKeyInfo -ErrorAction Stop
    if ($ek -and $ek.PublicKey -and $ek.PublicKey.RawData) {{
        [System.IO.File]::WriteAllBytes("{pubkey_path}", $ek.PublicKey.RawData)
        Write-Output "OK"
    }} else {{
        Write-Output "NO_RAWDATA"
    }}
}} catch {{
    Write-Output ("ERR: " + $_.Exception.Message)
}}
"""
    export_result = run_ps(ps_export, timeout=25)

    if os.path.exists(pubkey_path) and os.path.getsize(pubkey_path) > 0:
        try:
            return {"status": "ok", "source": "raw EK public key (ASN.1 RawData)",
                     "path": pubkey_path, **hash_file(pubkey_path)}
        except Exception:
            pass

    # --- Method 3: last resort, just the SHA256 Windows already has ---
    sha256_only = run_ps(
        "try { (Get-TpmEndorsementKeyInfo -HashAlgorithm Sha256 -ErrorAction Stop)."
        "PublicKeyHash } catch { 'N/A: ' + $_.Exception.Message }",
        timeout=20,
    )
    if sha256_only and not sha256_only.startswith("N/A") and "error" not in sha256_only.lower():
        return {
            "status": "partial",
            "note": ("Windows computed this SHA256 itself but won't hand over the "
                     "raw bytes behind it, so MD5/SHA1 aren't derivable here."),
            "sha256": sha256_only,
        }

    return {
        "status": "unavailable",
        "detail": (
            f"certutil: {result1}\n"
            f"  PowerShell export: {export_result}\n"
            f"  Most likely cause: fTPM without a factory EK cert or exportable "
            f"public key. Common on AMD/Intel firmware TPMs - hardware limit, "
            f"not something the script can fix."
        )
    }


def get_tpm_basic_info() -> str:
    return run_ps(
        "try { "
        "Get-Tpm | Select-Object TpmPresent, TpmReady, TpmEnabled, TpmActivated, "
        "ManufacturerId, ManufacturerIdTxt, ManufacturerVersion "
        "| Format-List | Out-String -Width 200 "
        "} catch { 'Get-Tpm unavailable: ' + $_.Exception.Message }"
    )


# =========================================================================
#  [8] Windows product key
# =========================================================================
# Two very different methods here, and the order matters a lot.
#
# OA3xOriginalProductKey is the one to trust: it's the OEM key that got
# burned into the motherboard firmware at the factory. If it's there, it's
# real, full stop. Problem is most machines don't have one - it's mainly a
# laptop-from-a-big-manufacturer thing. Build-it-yourself desktops, VMs,
# and a lot of newer installs running on a "digital license" (activated via
# Microsoft account or a hardware hash, no key involved at all) will just
# come back empty here.
#
# The DigitalProductId registry trick is the classic Windows 7/8-era method
# floating around every forum since 2010. Here's the catch that trips
# people up: this algorithm ALWAYS spits out something that looks like a
# valid 25-character key, whether or not there was a real key to decode in
# the first place. It's not "erroring out" on a digital-license machine -
# it's confidently decoding registry noise into a plausible-looking key that
# was never actually used to activate anything. So this is kept as a
# fallback only, and clearly flagged as unverified rather than presented
# with the same confidence as the firmware key.

def get_windows_product_key() -> dict:
    # --- Method 1: firmware key, trust this one if it shows up ---
    oa3_out = run_ps(
        "try { "
        "(Get-CimInstance -Query \"select * from SoftwareLicensingService\")."
        "OA3xOriginalProductKey "
        "} catch { '' }",
        timeout=20,
    )
    oa3_clean = oa3_out.strip() if oa3_out else ""

    # run_ps() wraps its own "nothing happened" messages in parentheses, e.g.
    # "(empty / not available)" - and those are long enough to accidentally
    # pass a naive length check. Learned that one the hard way after a first
    # pass reported "HIGH TRUST" on an empty key. Filtering those out here.
    is_placeholder = oa3_clean.startswith("(") or "error" in oa3_clean.lower()
    if oa3_clean and not is_placeholder and len(oa3_clean) >= 20:
        return {
            "status": "ok",
            "source": "firmware (OA3xOriginalProductKey)",
            "trust": "high",
            "key": oa3_clean,
        }

    # --- Method 2: the old registry decode, unverified by nature ---
    ps_script = r"""
$map = "BCDFGHJKMPQRTVWXY2346789"
try {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    $data = (Get-ItemProperty -Path $regPath -Name DigitalProductId -ErrorAction Stop).DigitalProductId
    $key = ""
    $isWin8 = ([math]::Floor($data[66] / 6)) -band 1
    $data[66] = ($data[66] -band 0xF7) -bor (($isWin8 -band 2) * 4)
    $last = 0
    for ($i = 24; $i -ge 0; $i--) {
        $cur = 0
        for ($j = 14; $j -ge 0; $j--) {
            $cur = $cur * 256
            $cur = $data[$j + 52] + $cur
            $data[$j + 52] = [math]::Floor($cur / 24)
            $cur = $cur % 24
            $last = $cur
        }
        $key = $map[$cur] + $key
    }
    if ($isWin8 -eq 1) {
        $keypart1 = $key.Substring(1, $last)
        $insert = "N"
        $key = $key.Insert($key.IndexOf($keypart1) + $keypart1.Length, $insert)
        if ($last -eq 0) { $key = $insert + $key }
    }
    $result = $key.Insert(5, "-").Insert(11, "-").Insert(17, "-").Insert(23, "-")
    Write-Output $result
} catch {
    Write-Output ("N/A: " + $_.Exception.Message)
}
"""
    legacy_out = run_ps(ps_script, timeout=20)
    legacy_is_placeholder = legacy_out.startswith("N/A") or legacy_out.startswith("(")
    if legacy_out and not legacy_is_placeholder:
        return {
            "status": "unverified",
            "source": "legacy DigitalProductId decode (Win7/8 algorithm)",
            "trust": "low",
            "key": legacy_out,
            "warning": (
                "This always produces a correctly-formatted key even when there's "
                "no real one to find - on digital-license installs it's frequently "
                "just wrong. Don't use it to reactivate anything without checking "
                "first."
            ),
        }

    return {"status": "unavailable", "detail": legacy_out or "no data returned"}


# =========================================================================
#  Main
# =========================================================================

def main():
    _enable_ansi_on_windows()
    banner()

    if platform.system() != "Windows":
        error("This script relies on WMI/PowerShell/certutil and must be run on Windows.")
        sys.exit(1)

    admin_status = is_admin()
    if admin_status:
        ok("Running with Administrator privileges")
    else:
        warn("Not running as Administrator - sections [6] and [8] may be limited")

    # [1] Physical disks
    section("Disk / HDD / SSD Serial Numbers", "◈")
    raw(run_ps(
        "Get-CimInstance Win32_DiskDrive | "
        "Select-Object Name, SerialNumber, Model | Format-Table -AutoSize | Out-String -Width 200"
    ))

    # [2] Volumes - separate from physical disks since one disk can have
    # multiple partitions/volumes with their own serials
    section("Disks & Volumes", "◈")
    raw(run_ps(
        "Get-CimInstance Win32_LogicalDisk | "
        "Select-Object DeviceID, VolumeSerialNumber | Format-Table -AutoSize | Out-String -Width 200"
    ))

    # [3] SMBIOS - board-level identifiers, survive OS reinstalls
    section("SMBIOS", "◈")
    kv("UUID", run_ps("(Get-CimInstance Win32_ComputerSystemProduct).UUID"), C.CYAN)
    kv("BIOS Serial Number", run_ps("(Get-CimInstance Win32_BIOS).SerialNumber"), C.CYAN)
    kv("Chassis Serial Number", run_ps("(Get-CimInstance Win32_SystemEnclosure).SerialNumber"), C.CYAN)

    # [4] MAC addresses - grabs everything including virtual adapters
    # (WAN Miniports etc), which is a bit noisy but at least it's complete
    section("MAC Address(es)", "◈")
    raw(run_ps(
        "Get-CimInstance Win32_NetworkAdapter | "
        "Where-Object { $_.MACAddress } | "
        "Select-Object Name, MACAddress | Format-Table -AutoSize | Out-String -Width 200"
    ))

    # [5] CPU/GPU
    section("CPU / GPU", "◈")
    print(f"  {C.ORANGE}{C.BOLD}CPU:{C.RESET}")
    raw(run_ps(
        "Get-CimInstance Win32_Processor | "
        "Select-Object Name, ProcessorId | Format-Table -AutoSize | Out-String -Width 200"
    ))
    print(f"  {C.ORANGE}{C.BOLD}GPU:{C.RESET}")
    raw(run_ps(
        "Get-CimInstance Win32_VideoController | "
        "Select-Object Name, PNPDeviceID | Format-Table -AutoSize | Out-String -Width 200"
    ))

    # [6] TPM - see the wall of comments above get_tpm_ek_hashes() for why
    # this one is more involved than it probably looks like it should be
    section("TPM Module Information", "◈")
    print(f"  {C.ORANGE}{C.BOLD}General info:{C.RESET}")
    raw(get_tpm_basic_info())
    print(f"  {C.ORANGE}{C.BOLD}EK (Endorsement Key) hashes:{C.RESET}")
    ek = get_tpm_ek_hashes()
    if ek.get("status") == "ok":
        kv("Source", ek["source"], C.GREEN)
        kv("File", ek["path"], C.GRAY)
        kv("MD5", ek["md5"], C.YELLOW)
        kv("SHA1", ek["sha1"], C.YELLOW)
        kv("SHA256", ek["sha256"], C.YELLOW)
    elif ek.get("status") == "partial":
        kv("SHA256 (Windows-computed)", ek["sha256"], C.YELLOW)
        info(ek["note"])
    else:
        error("Not available")
        print(f"  {C.GRAY}{ek.get('detail', 'unknown')}{C.RESET}")

    # [7] RAM - serials are frequently just zeros on consumer sticks, that's
    # normal and not something to worry about, most vendors don't bother
    section("Memory / RAM", "◈")
    raw(run_ps(
        "Get-CimInstance Win32_PhysicalMemory | "
        "Select-Object BankLabel, DeviceLocator, @{N='CapacityGB';E={$_.Capacity/1GB}}, SerialNumber "
        "| Format-Table -AutoSize | Out-String -Width 200"
    ))

    # [8] Product key - see the big comment block above get_windows_product_key()
    section("Windows Product ID & Key", "◈")
    kv("Product ID", run_ps("(Get-CimInstance Win32_OperatingSystem).SerialNumber"), C.CYAN)
    pk = get_windows_product_key()
    if pk["status"] == "ok":
        ok(f"Product Key ({pk['source']}) - HIGH TRUST")
        kv("Key", pk["key"], C.GREEN)
    elif pk["status"] == "unverified":
        warn(f"Product Key ({pk['source']}) - LOW TRUST / UNVERIFIED")
        kv("Key", pk["key"], C.YELLOW)
        print(f"  {C.RED}{pk['warning']}{C.RESET}")
    else:
        error("No product key could be retrieved")
        print(f"  {C.GRAY}{pk.get('detail', 'unknown')}{C.RESET}")

    print()
    print(f"{C.DIM}  Note: on Windows 10/11 with an OEM/Microsoft-account-linked digital{C.RESET}")
    print(f"{C.DIM}  license, there is often NO plaintext 25-character key at all -{C.RESET}")
    print(f"{C.DIM}  activation happens via a hardware hash sent to Microsoft's servers.{C.RESET}")

    print()
    print(f"{C.MAGENTA}{C.BOLD}{'═' * 70}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}  NXINF - Report complete{C.RESET}")
    print(f"{C.MAGENTA}{C.BOLD}{'═' * 70}{C.RESET}")
    if not admin_status:
        warn("Re-run as Administrator for maximum reliability on [6] and [8].")


def _wait_before_exit():
    # Double-clicking the exe (or the .py, if someone's got file associations
    # set up) opens a console, runs the script, and Windows slams the window
    # shut the instant main() returns - nobody gets a chance to actually read
    # any of this. A plain input() prompt is the easiest fix: it just sits
    # there until the user hits Enter, no extra imports needed.
    #
    # Wrapped in try/except because this can get run in contexts where stdin
    # isn't interactive (piped output, some CI runner, whatever) - in that
    # case input() raises EOFError instead of hanging forever, and we just
    # want to exit cleanly rather than crash with a traceback on the way out.
    try:
        print()
        input(f"{C.DIM}Press Enter to close...{C.RESET}")
    except (EOFError, KeyboardInterrupt):
        pass


if __name__ == "__main__":
    # Also wrap main() itself - if something blows up with an unhandled
    # exception (shouldn't happen given how defensively the PS/cmd calls
    # are wrapped, but "shouldn't" isn't "can't"), we still want the window
    # to stick around long enough to actually read the traceback instead of
    # it flashing past in half a second.
    try:
        main()
    except Exception:
        import traceback
        traceback.print_exc()
    _wait_before_exit()
#PLEASE DON'T STEAL MY CODE


import subprocess
import sys
import os
import ctypes
import platform
import hashlib
import tempfile




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

    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11) 
        mode = ctypes.c_uint32()
        kernel32.GetConsoleMode(handle, ctypes.byref(mode))
        kernel32.SetConsoleMode(handle, mode.value | 0x0004)  
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




def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
       
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




def get_tpm_ek_hashes() -> dict:
#created By Nxth9n / github.com/nxthxndev

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

    export_result = run_ps(ps_export, timeout=25)

    if os.path.exists(pubkey_path) and os.path.getsize(pubkey_path) > 0:
        try:
            return {"status": "ok", "source": "raw EK public key (ASN.1 RawData)",
                     "path": pubkey_path, **hash_file(pubkey_path)}
        except Exception:
            pass

    
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



def get_windows_product_key() -> dict:
    
    oa3_out = run_ps(
        "try { "
        "(Get-CimInstance -Query \"select * from SoftwareLicensingService\")."
        "OA3xOriginalProductKey "
        "} catch { '' }",
        timeout=20,
    )
    oa3_clean = oa3_out.strip() if oa3_out else ""


    is_placeholder = oa3_clean.startswith("(") or "error" in oa3_clean.lower()
    if oa3_clean and not is_placeholder and len(oa3_clean) >= 20:
        return {
            "status": "ok",
            "source": "firmware (OA3xOriginalProductKey)",
            "trust": "high",
            "key": oa3_clean,
        }


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


    section("Disk / HDD / SSD Serial Numbers", "◈")
    raw(run_ps(
        "Get-CimInstance Win32_DiskDrive | "
        "Select-Object Name, SerialNumber, Model | Format-Table -AutoSize | Out-String -Width 200"
    ))


    section("Disks & Volumes", "◈")
    raw(run_ps(
        "Get-CimInstance Win32_LogicalDisk | "
        "Select-Object DeviceID, VolumeSerialNumber | Format-Table -AutoSize | Out-String -Width 200"
    ))


    section("SMBIOS", "◈")
    kv("UUID", run_ps("(Get-CimInstance Win32_ComputerSystemProduct).UUID"), C.CYAN)
    kv("BIOS Serial Number", run_ps("(Get-CimInstance Win32_BIOS).SerialNumber"), C.CYAN)
    kv("Chassis Serial Number", run_ps("(Get-CimInstance Win32_SystemEnclosure).SerialNumber"), C.CYAN)


    section("MAC Address(es)", "◈")
    raw(run_ps(
        "Get-CimInstance Win32_NetworkAdapter | "
        "Where-Object { $_.MACAddress } | "
        "Select-Object Name, MACAddress | Format-Table -AutoSize | Out-String -Width 200"
    ))


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



    section("Memory / RAM", "◈")
    raw(run_ps(
        "Get-CimInstance Win32_PhysicalMemory | "
        "Select-Object BankLabel, DeviceLocator, @{N='CapacityGB';E={$_.Capacity/1GB}}, SerialNumber "
        "| Format-Table -AutoSize | Out-String -Width 200"
    ))

 
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

    try:
        print()
        input(f"{C.DIM}Press Enter to close...{C.RESET}")
    except (EOFError, KeyboardInterrupt):
        pass


if __name__ == "__main__":

    try:
        main()
    except Exception:
        import traceback
        traceback.print_exc()
    _wait_before_exit()

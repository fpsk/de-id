#!/usr/bin/env python3
"""
Portable Windows 11 Single-File Executable Builder (`HIPAA_DeID_Studio.exe`).

Packages the entire HIPAA Safe Harbor De-Identification Studio source code
(`webapp.py`, `app.py`, `cli.py`, `deid_engine/`, `templates/index.html`, and
`requirements.txt`) into a self-contained 64-bit Windows PE executable
(`HIPAA_DeID_Studio.exe`) that requires zero pre-installed Python or Admin
privileges on Windows 11.
"""

import base64
import io
import os
import struct
import zipfile
from pathlib import Path


def _locate_t64_launcher() -> bytes:
    """Locate the 64-bit Windows PEP 397/distlib launcher stub (`t64.exe`)."""
    candidates = []
    try:
        import pip._vendor.distlib as distlib_mod
        candidates.append(Path(distlib_mod.__file__).resolve().parent / "t64.exe")
    except Exception:
        pass

    candidates.extend([
        Path("/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/lib/python3.9/site-packages/pip/_vendor/distlib/t64.exe"),
        Path("/usr/local/lib/python3/dist-packages/pip/_vendor/distlib/t64.exe"),
    ])

    for path in candidates:
        if path.is_file():
            return path.read_bytes()

    raise FileNotFoundError("Could not locate pip._vendor.distlib t64.exe stub.")


def build_portable_exe(base_dir: Path | None = None) -> Path:
    if base_dir is None:
        base_dir = Path(__file__).resolve().parent

    app_files = [
        "README.md",
        "requirements.txt",
        "app.py",
        "webapp.py",
        "cli.py",
        "deid_engine/__init__.py",
        "deid_engine/spatial_parser.py",
        "deid_engine/whitelist.py",
        "deid_engine/phi_detector.py",
        "deid_engine/tokenizer.py",
        "deid_engine/pdf_redactor.py",
        "deid_engine/vault.py",
        "deid_engine/reverser.py",
        "templates/index.html",
    ]

    # 1. Create compressed inner ZIP containing all application source files
    inner_zip_buf = io.BytesIO()
    with zipfile.ZipFile(inner_zip_buf, "w", zipfile.ZIP_DEFLATED) as izf:
        for rel in app_files:
            izf.write(base_dir / rel, rel)
    app_b64 = base64.b64encode(inner_zip_buf.getvalue()).decode("ascii")

    # 2. Build self-contained PowerShell bootstrapper stored inside outer ZIP
    ps_script = f"""#PSBOOT
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$ExePath = ([Environment]::CommandLine -split [char]34)[3]
$RootDir = Split-Path -Parent $ExePath
if (-not $RootDir) {{ $RootDir = Get-Location }}
Set-Location $RootDir

Write-Host '========================================================================' -ForegroundColor Cyan
Write-Host '  HIPAA Safe Harbor PDF De-Identification Studio (Windows 11 Portable)  ' -ForegroundColor Cyan
Write-Host '========================================================================' -ForegroundColor Cyan

# Extract embedded application payload
$AppPayloadB64 = '{app_b64}'
$AppZipPath = Join-Path $RootDir '_app_payload.zip'
[IO.File]::WriteAllBytes($AppZipPath, [Convert]::FromBase64String($AppPayloadB64))
Expand-Archive -Path $AppZipPath -DestinationPath $RootDir -Force
Remove-Item $AppZipPath -Force -ErrorAction SilentlyContinue

# Check for existing portable Python runtime
$PyExe = Join-Path $RootDir '_runtime\\python.exe'
if (-not (Test-Path $PyExe)) {{
    Write-Host '[1/3] Setting up zero-install Portable Python 3.11 runtime...' -ForegroundColor Yellow
    $RuntimeDir = Join-Path $RootDir '_runtime'
    New-Item -ItemType Directory -Path $RuntimeDir -Force | Out-Null

    $PyZipUrl = 'https://www.python.org/ftp/python/3.11.9/python-3.11.9-embed-amd64.zip'
    $PyZipFile = Join-Path $RuntimeDir 'py_embed.zip'
    Invoke-WebRequest -Uri $PyZipUrl -OutFile $PyZipFile -UseBasicParsing
    Expand-Archive -Path $PyZipFile -DestinationPath $RuntimeDir -Force
    Remove-Item $PyZipFile -Force

    # Enable site-packages in python311._pth
    $PthFile = Join-Path $RuntimeDir 'python311._pth'
    (Get-Content $PthFile) -replace '#import site', 'import site' | Set-Content $PthFile

    Write-Host '[2/3] Bootstrapping package manager (pip)...' -ForegroundColor Yellow
    $GetPipUrl = 'https://bootstrap.pypa.io/get-pip.py'
    $GetPipFile = Join-Path $RuntimeDir 'get-pip.py'
    Invoke-WebRequest -Uri $GetPipUrl -OutFile $GetPipFile -UseBasicParsing
    & $PyExe $GetPipFile --no-warn-script-location
    Remove-Item $GetPipFile -Force

    Write-Host '[3/3] Installing PDF redaction & encryption engine (PyMuPDF, Cryptography, Flask)...' -ForegroundColor Yellow
    & $PyExe -m pip install --no-warn-script-location -r (Join-Path $RootDir 'requirements.txt')
}}

Write-Host ''
Write-Host 'Launching HIPAA Safe Harbor Web Studio at http://127.0.0.1:5050 ...' -ForegroundColor Green
& $PyExe (Join-Path $RootDir 'webapp.py') --open-browser
#PSBOOT
"""

    outer_zip_buf = io.BytesIO()
    with zipfile.ZipFile(outer_zip_buf, "w", zipfile.ZIP_STORED) as ozf:
        ozf.writestr("__main__.py", ps_script.encode("utf-8"))

    zip_bytes = outer_zip_buf.getvalue()
    launcher_bytes = _locate_t64_launcher()
    shebang = (
        b"#!/usr/bin/env powershell.exe -NoP -ep Bypass -c "
        b"$p=([Environment]::CommandLine-split[char]34)[3];"
        b"iex(([IO.File]::ReadAllText($p)-split('#'+'PSBOOT'))[1]);#\r\n"
    )

    assert len(shebang) <= 255, f"Shebang too long: {len(shebang)}"
    exe_bytes = launcher_bytes + shebang + zip_bytes

    out_exe = base_dir / "HIPAA_DeID_Studio.exe"
    out_exe.write_bytes(exe_bytes)

    # Verify PE + EOCD offsets and payload extraction
    eocd_pos = exe_bytes.rfind(b"PK\x05\x06")
    cd_size, cd_offset = struct.unpack("<II", exe_bytes[eocd_pos + 12 : eocd_pos + 20])
    computed_archive_start = eocd_pos - (cd_size + cd_offset)
    actual_archive_start = len(launcher_bytes) + len(shebang)
    assert computed_archive_start == actual_archive_start

    decoded = exe_bytes.decode("utf-8", errors="replace")
    parts = decoded.split("#" + "PSBOOT")
    assert len(parts) == 3 and "HIPAA Safe Harbor" in parts[1]

    print(f"Built standalone {out_exe} ({len(exe_bytes) / 1024:.1f} KB)")
    return out_exe


if __name__ == "__main__":
    build_portable_exe()

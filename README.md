# HIPAA Safe Harbor PDF De-Identification & Reversal Studio (Local Non-LLM)

A 100% local, deterministic (non-LLM) clinical PDF de-identification and reversal application for **Windows 11** and **macOS**.

## Key Capabilities
- **100% Local & Offline**: No cloud APIs, no LLMs, and no GPU required. Runs in <1 second per PDF on any standard Windows 11 notebook or Mac.
- **Physical PDF Stream Redaction**: Uses `PyMuPDF` to physically remove underlying text glyphs while preserving clean template artwork and table borders.
- **Bilingual Support**: Handles both English and Traditional/Simplified Chinese clinical reports (e.g., FoundationOne Liquid CDx, pathology reports, lab panels).
- **Reversible Key Vault (HIPAA § 164.514(c))**: Generates a local `reid_key_vault.json` (with optional AES-256 password encryption) so you can:
  1. Combine **Key Vault + De-Identified PDF** to restore the original PDF.
  2. Combine **Key Vault + Cloud Analysis Output (`.csv`, `.json`, `.md`, `.txt`)** to re-identify patient tokens (`PAT-XXXXXX`, `MRN-XXXXXX`, etc.).

---

## Quick Start on Windows 11 Notebook

### Option A (Zero Installation): Double-Click `HIPAA_DeID_Studio.exe`
1. Download or clone this repository and double-click **`HIPAA_DeID_Studio.exe`**.
   *(If Windows SmartScreen shows a prompt for an unsigned binary, click **"More info" -> "Run anyway"**.)*
2. On first launch, it automatically sets up a local Portable Python 3.11 runtime inside `_runtime\` (no system Python or Admin privileges needed) and opens **`http://127.0.0.1:5050`** in your browser.
3. To rebuild `HIPAA_DeID_Studio.exe` from source after modifying the code, run:
   ```bash
   python3 build_portable_exe.py
   ```

### Option B: Launch with System Python via `.bat`
If you have **Python 3.10+** installed from [python.org/downloads/windows](https://www.python.org/downloads/windows/) (with **"Add python.exe to PATH"** checked):
- Double-click **`run_windows_webapp.bat`** to start the Local Web Studio (`http://127.0.0.1:5050`).
- Or double-click **`run_windows_desktop.bat`** to open the native Windows Desktop GUI.

### Option C: Launch via Command Prompt / PowerShell
Open Command Prompt or PowerShell inside this folder and run:
```powershell
pip install -r requirements.txt
python webapp.py --open-browser
```

### Option D: Build a PyInstaller `.exe`
Double-click **`build_windows_exe.bat`** on any Windows PC with Python installed to build:
- `dist\HIPAA_DeID_WebApp.exe`
- `dist\HIPAA_DeID_Desktop.exe`

---

## Quick Start on macOS

Double-click **`run_mac_webapp.command`** or run in Terminal:
```bash
pip3 install -r requirements.txt
python3 webapp.py --open-browser
```

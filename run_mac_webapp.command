#!/bin/bash
cd "$(dirname "$0")"
echo "============================================================================"
echo "  HIPAA Safe Harbor PDF De-Identification Studio - macOS Web Launcher"
echo "============================================================================"
python3 -m pip install -q -r requirements.txt
python3 webapp.py --open-browser

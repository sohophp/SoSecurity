#!/usr/bin/env python3
import os
from pathlib import Path
import subprocess
import sys
from isolated_demo import demo_server

runtime = sys.argv[1] if len(sys.argv) > 1 else 'php'
with demo_server(runtime) as url:
    subprocess.run(['node', str(Path(__file__).with_name('mfa-browser.cjs')), url], env=os.environ.copy(), check=True)

#!/usr/bin/env python3
"""Finite format-3 real TLS/browser host and three process-death points."""
from pathlib import Path
import subprocess,sys
ROOT=Path(__file__).resolve().parent.parent
runtime=sys.argv[1];backend=sys.argv[2] if len(sys.argv)>2 else 'sqlite'
assert backend in ['sqlite','mysql']
subprocess.run(['python3',str(ROOT/'tests/state_http.py'),runtime,'--backend',backend,'--business','--tls','--browser'],cwd=ROOT,check=True)
subprocess.run(['python3',str(ROOT/'tests/business_crash.py'),runtime,backend],cwd=ROOT,check=True)
print('PASS bounded business host integration: format 3 TLS/Chromium, 3 SIGKILL points and one concurrent writer; no final recovery claim',flush=True)

#!/usr/bin/env python3
import argparse
import os
from pathlib import Path
import subprocess
from isolated_demo import demo_server
parser=argparse.ArgumentParser();parser.add_argument('runtime',nargs='?',default='php');parser.add_argument('--url');args=parser.parse_args()
def acceptance(url): subprocess.run(['node',str(Path(__file__).with_name('auth-browser.cjs')),url],env=os.environ.copy(),check=True)
if args.url: acceptance(args.url.rstrip('/')+'/')
else:
    with demo_server(args.runtime) as url: acceptance(url)

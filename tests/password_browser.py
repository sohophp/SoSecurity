#!/usr/bin/env python3
import argparse,os,subprocess
from pathlib import Path
from isolated_demo import demo_server
parser=argparse.ArgumentParser();parser.add_argument('runtime',nargs='?',default='php');parser.add_argument('--url');args=parser.parse_args()
def run(url):subprocess.run(['node',str(Path(__file__).with_name('password-browser.cjs')),url.rstrip('/')+'/'],env=os.environ.copy(),check=True)
if args.url:run(args.url)
else:
    with demo_server(args.runtime) as url:run(url)

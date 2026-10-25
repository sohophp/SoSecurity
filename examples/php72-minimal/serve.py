#!/usr/bin/env python3
"""Serve only this local demo's public directory on 127.0.0.1."""
import argparse,json,os,pathlib,subprocess
ROOT=pathlib.Path(__file__).resolve().parent
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--port',type=int,default=8080);args=parser.parse_args()
    assert 1<=args.port<=65535,'Invalid port'
    cfg=json.loads((ROOT/'var/config.json').read_text())
    env={k:v for k,v in os.environ.items() if not k.startswith('SOSECURITY_') and k not in ['PHPRC','PHP_INI_SCAN_DIR','PHP_CLI_SERVER_WORKERS']}
    env.update(SOSECURITY_EXAMPLE_STORE=cfg['state'],SOSECURITY_EXAMPLE_USER=cfg['username'],SOSECURITY_EXAMPLE_PASSWORD_HASH=cfg['password_hash'],SOSECURITY_EXAMPLE_HTTPS='0')
    command=[cfg['php'],'-d','session.save_path='+cfg['sessions'],'-d','display_errors=0','-S','127.0.0.1:'+str(args.port),'-t',str(ROOT/'public')]
    child=subprocess.Popen(command,cwd=str(ROOT),env=env)
    try:return child.wait()
    except KeyboardInterrupt:return 0
    finally:
        if child.poll() is None:
            child.terminate()
            try:child.wait(timeout=5)
            except subprocess.TimeoutExpired:child.kill();child.wait()
if __name__=='__main__':raise SystemExit(main())

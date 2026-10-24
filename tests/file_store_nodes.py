"""Bounded subprocess tests for owned FIFO nodes; never reads an existing storage directory."""
from pathlib import Path
import hashlib,json,os,subprocess,sys,tempfile
root=Path(__file__).resolve().parent.parent
logs=None
if len(sys.argv)==2:
    logs=tempfile.TemporaryDirectory(prefix='sosecurity-file-nodes-logs-');out=Path(logs.name)/'result.json';prefix=Path(logs.name)/'log';runtimes=sys.argv[1:]
elif len(sys.argv)>=4:out=Path(sys.argv[1]).resolve();prefix=Path(sys.argv[2]).resolve();runtimes=sys.argv[3:]
else:raise SystemExit('Usage: file_store_nodes.py [NEW_OUTPUT_JSON LOG_PREFIX] PHP_RUNTIME ...')
assert out.parent.is_dir() and not out.exists()
rows=[]
with tempfile.TemporaryDirectory(prefix='sosecurity-file-nodes-') as work:
    owned=Path(work);(owned/'owned-test').write_text('Owned subprocess FIFO tests only\n')
    for runtime in runtimes:
        for name in ['value-fifo','lock-fifo','prune-fifo','value-race','lock-race','prune-race']:
            directory=owned/name;directory.mkdir(mode=0o700)
            digest=hashlib.sha256(b'owned-nodes\x00key').hexdigest()
            node=directory/('lock-'+str(int(digest[:2],16)%64) if name.startswith('lock-') else digest+'.json')
            if name.endswith('-fifo'):os.mkfifo(str(node),0o600)
            else:
                node.write_text('' if name.startswith('lock-') else '{"expires":0,"value":{"owned":true}}');node.chmod(0o600)
            log=Path(str(prefix)+'-'+Path(runtime).name+'-'+name+'.log');assert not log.exists()
            command=[runtime,'-d','memory_limit=8M',str(root/'tests/file-store-nodes.php'),str(directory),name]
            with log.open('x') as handle:
                process=subprocess.Popen(command,cwd=root,stdout=handle,stderr=subprocess.STDOUT)
                timeout=False
                try:code=process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    timeout=True;process.terminate()
                    try:code=process.wait(timeout=5)
                    except subprocess.TimeoutExpired:process.kill();code=process.wait(timeout=5)
            passed=not timeout and code==0 and 'PASS file store node ' in log.read_text()
            rows.append(dict(command=command,exit=code,timed_out=timeout,passed=passed,child_terminal=process.poll() is not None));print(Path(runtime).name,name,'timeout' if timeout else code,flush=True)
            if not passed:print(log.read_text(),flush=True)
            for entry in directory.iterdir():entry.unlink()
            directory.rmdir()
    cleaned_children=all(r['child_terminal'] for r in rows)
out.write_text(json.dumps(dict(rows=rows,children_terminal=cleaned_children,temporary_directory=work,cleaned=not Path(work).exists()),indent=2)+'\n')
if logs is not None:print(out.read_text());logs.cleanup()
raise SystemExit(0 if cleaned_children and all(r['passed'] for r in rows) else 1)

#!/usr/bin/env python3
"""Execute isolated probes, verify budgets/results/import safety and absence of real-password inputs."""
import json, os, subprocess, sys, time
from pathlib import Path
runtime=sys.argv[1] if len(sys.argv)>1 else 'php';root=Path(__file__).resolve().parent.parent;entry=str(root/'examples/password-calibrate.php');checks=0
def check(expected,actual):
    global checks
    checks+=1;assert expected==actual,(expected,actual)
for profile in ['bcrypt','argon2id']:
    available=profile=='bcrypt' or subprocess.call([runtime,'-r','exit(defined("PASSWORD_ARGON2ID")?0:1);'])==0
    start=time.monotonic();result=subprocess.run([runtime,entry,'--profile='+profile,'--target-ms=100','--budget-ms=1500','--samples=1'],capture_output=True,text=True,timeout=5)
    if not available:check(1,result.returncode);print('NOT APPLICABLE Argon2id calibration: explicit unavailable-profile refusal verified');continue
    check(0,result.returncode);check('',result.stderr);data=json.loads(result.stdout);check(profile,data['profile']);check(False,data['writes_configuration']);check(True,time.monotonic()-start<3)
    check(True,all(len(m['samples_ms'])==1 and m['median_ms']>0 for m in data['measurements']))
    if data['recommended'] is not None:
        check(True,any(m['options']==data['recommended'] and m['median_ms']<=100 for m in data['measurements']))
    check(False,any(word in data for word in ['password','hash','secret']))
    # Process deadline may yield no completed probe; that is explicit, never a fabricated recommendation.
result=subprocess.run([runtime,entry,'--target-ms=2000','--budget-ms=100','--samples=5'],capture_output=True,text=True,timeout=3)
check(0,result.returncode);data=json.loads(result.stdout);check('password.calibration_budget',data['reason'])
check(True,data['recommended'] is None or any(m['options']==data['recommended'] and m['median_ms']<=2000 for m in data['measurements']))
for bad in ['--password=secret','--profile=unknown','--samples=0','--budget-ms=999999','--target-ms=1','--samples=1 --samples=1']:
    result=subprocess.run([runtime,entry,*bad.split()],capture_output=True,text=True,timeout=3);check(1,result.returncode);check('',result.stdout);check(False,'secret' in result.stderr)
result=subprocess.run([runtime,'-r','require $argv[1]; echo "import-safe";',entry],capture_output=True,text=True,timeout=3)
check(0,result.returncode);check('import-safe',result.stdout);check('',result.stderr)
result=subprocess.run([runtime,'-d','disable_functions=proc_open',entry],capture_output=True,text=True,timeout=3)
check(1,result.returncode);check('',result.stdout)
print(f'PASS isolated password calibration: {checks} assertions on {runtime}; bounded child lifetime, explicit profiles, no secret arguments/output or configuration writes')

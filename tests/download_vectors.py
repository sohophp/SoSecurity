#!/usr/bin/env python3
"""Independent arbitrary-precision Python model for public single-range responses and overflow refusal."""
import json,random,re,subprocess,sys
from pathlib import Path
runtime=sys.argv[1] if len(sys.argv)>1 else 'php';root=Path(__file__).resolve().parent.parent
randomizer=random.Random(904266);vectors=[];expected=[]
for size in [0,1,2,10,100,4096,20971520]:
    ranges=['bytes=-','bytes=0-0,2-3','items=0-1','bytes=999999999999999999999-','bytes=-0','bytes=0-','bytes=-99999999999999999999','bytes=0-99999999999999999999']
    for unused in range(200):
        start=randomizer.choice([0,max(0,size-1),size,size+1,randomizer.randrange(max(2,size*2)),99999999999999999999]);end=randomizer.choice([None,0,max(0,size-1),size+1,99999999999999999999])
        ranges.append(('bytes=-'+str(start)) if randomizer.randrange(3)==0 else 'bytes='+str(start)+'-'+('' if end is None else str(end)))
    for value in ranges:
        vectors.append({'size':size,'range':value});match=re.fullmatch(r'bytes=([0-9]{0,20})-([0-9]{0,20})',value)
        if not match or not any(match.groups()):expected.append({'status':'range','total':None});continue
        left,right=match.groups();invalid=size==0
        if not left:
            count=int(right);invalid=invalid or count==0;start=max(0,size-count);end=size-1
        else:
            start=int(left);end=size-1 if not right else min(int(right),size-1);invalid=invalid or start>=size or end<start
        expected.append({'status':'range','total':size} if invalid else {'status':206,'length':end-start+1,'range':f'bytes {start}-{end}/{size}'})
actual=json.loads(subprocess.check_output([runtime,str(root/'tests/download-vectors.php')],input=json.dumps(vectors).encode(),timeout=30))
assert len(expected)==len(actual)
for index,(want,got) in enumerate(zip(expected,actual)):assert want==got,(vectors[index],want,got)
print(f'PASS independent download ranges: {len(vectors)} Python arbitrary-precision vectors on {runtime}; zero/end/suffix, open ranges, unsatisfiable and 20-digit bounds')

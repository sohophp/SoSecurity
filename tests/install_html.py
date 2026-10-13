#!/usr/bin/env python3
"""Fresh consumer with explicitly selected optional sanitizer dependency; no tools/demo autoloader reuse."""
import json, subprocess, sys, tempfile
from pathlib import Path
root=Path(__file__).resolve().parent.parent;runtime=sys.argv[1] if len(sys.argv)>1 else 'php72';composer=sys.argv[2] if len(sys.argv)>2 else '/usr/local/bin/composer'
with tempfile.TemporaryDirectory(prefix='sosecurity-html-install-') as directory:
    path=Path(directory);manifest={'name':'sosecurity/html-integration-consumer','repositories':[{'type':'path','url':str(root),'options':{'symlink':False}}],'require':{'sohophp/sosecurity':'@dev','ezyang/htmlpurifier':'^4.19.1'},'config':{'allow-plugins':False}}
    (path/'composer.json').write_text(json.dumps(manifest));result=subprocess.run([runtime,composer,'install','--working-dir='+directory,'--no-interaction','--no-progress'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    if result.returncode:raise RuntimeError(result.stdout.decode()+result.stderr.decode())
    (path/'verify.php').write_text('''<?php
declare(strict_types=1);
require __DIR__.'/vendor/autoload.php';
require __DIR__.'/vendor/sohophp/sosecurity/examples/rich-text.php';
$security=SoSecurity\\Security::fromArray(['site'=>'consumer','html'=>[]]);
$result=SoSecurity\\Examples\\cleanRichText($security->htmlCleaner(),'<p onclick="bad()">中文<strong>正常</strong><script>bad()</script><a href="javascript:bad()">坏链接</a></p>');
if ($result!=='<p>中文<strong>正常</strong><a>坏链接</a></p>') { exit(1); }
echo 'PASS optional HTML consumer: own Composer dependency/autoload and framework-free helper on PHP '.PHP_VERSION."\\n";
''')
    subprocess.run([runtime,str(path/'verify.php')],check=True)
    subprocess.run([runtime,composer,'audit','--working-dir='+directory,'--locked'],check=True)

#!/usr/bin/env python3
"""Exercise installed snapshot APIs using only private synthetic SQLite/file data."""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parent.parent
runtime = sys.argv[1] if len(sys.argv) > 1 else "php"
composer = sys.argv[2] if len(sys.argv) > 2 else "/usr/local/bin/composer"
with tempfile.TemporaryDirectory(prefix="sosecurity-snapshot-consumer-") as directory:
    work = Path(directory)
    (work / "composer.json").write_text(json.dumps({
        "name": "sosecurity/snapshot-consumer",
        "repositories": [{"type": "path", "url": str(root), "options": {"symlink": False}}],
        "require": {"sohophp/sosecurity": "@dev"},
        "config": {"allow-plugins": False},
    }))
    result = subprocess.run([runtime, composer, "install", "--working-dir=" + directory,
                             "--no-interaction", "--no-progress", "--no-scripts", "--no-plugins"],
                            capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    (work / "consumer.php").write_text(r'''<?php
declare(strict_types=1);
require __DIR__.'/vendor/autoload.php';
function verifySnapshot($ok):void{if($ok!==true){throw new RuntimeException('Installed snapshot consumer failed');}}
$package=__DIR__.'/vendor/sohophp/sosecurity';
$class=new ReflectionClass(SoSecurity\Account\SqlStateSnapshot::class);
verifySnapshot(strpos(realpath($class->getFileName()),realpath($package).DIRECTORY_SEPARATOR)===0);
mkdir(__DIR__.'/state',0700);mkdir(__DIR__.'/scratch',0700);
$pdo=new PDO('sqlite:'.__DIR__.'/consumer.sqlite',null,null,[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
chmod(__DIR__.'/consumer.sqlite',0600);
$pdo->exec(file_get_contents($package.'/resources/sql/state-snapshot-example-sqlite.sql'));
$pdo->exec("INSERT INTO snapshot_example VALUES('tenant','demo',1)");
$store=new SoSecurity\Storage\FileStore(__DIR__.'/state','installed-consumer');
$store->transact('session',static function():SoSecurity\Storage\Change{return new SoSecurity\Storage\Change(['binary'=>"a\0b"],0,true);});
$build=require $package.'/examples/state-snapshot.php';$source=$build($pdo,$store,__DIR__.'/state',__DIR__.'/scratch');
$view=$source->capture(['accounts'=>['account'=>['table'=>'snapshot_example','key'=>['scope'=>'tenant','subject'=>'demo'],'columns'=>['enabled']]],'files'=>['session'=>$store->snapshotFile('session')]]);
verifySnapshot($view->part('accounts')->row('account')===['enabled'=>1]);
$raw=$view->part('files')->file('session');verifySnapshot(json_decode($raw,true)['value']['binary']==="a\0b");
verifySnapshot($source->digest()===$view->digest());
verifySnapshot(file_get_contents(__DIR__.'/state/'.$store->snapshotFile('session'))===$raw);
verifySnapshot((int)$pdo->query('SELECT COUNT(*) FROM snapshot_example')->fetchColumn()===1);
verifySnapshot(glob(__DIR__.'/scratch/*')===[]);
echo 'PASS installed snapshot example: isolated class loading, SQL/file bytes and no data mutations PHP '.PHP_VERSION."\n";
''')
    result = subprocess.run([runtime, "-d", "memory_limit=8M", str(work / "consumer.php")],
                            cwd=work, capture_output=True, text=True)
    print(result.stdout + result.stderr, end="")
    if result.returncode:
        raise RuntimeError("Installed snapshot consumer exited " + str(result.returncode))

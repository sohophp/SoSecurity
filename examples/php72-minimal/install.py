#!/usr/bin/env python3
"""One fresh offline PHP7.2 consumer; only the pinned, already accepted local ZIP."""
import argparse,hashlib,json,os,pathlib,secrets,shutil,stat,subprocess,zipfile
ROOT=pathlib.Path(__file__).resolve().parent
PACKAGE_SHA256='0ec1b95079603f53c81a9320eb209bd79e9f5e38f6ccfbef71f4a915a55b83d5'
PACKAGE_COMMIT='46fa6d44df312082ae77da361186b9cb7dbd0ab3'
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def environment():
    env={k:v for k,v in os.environ.items() if not k.startswith(('SOSECURITY_','COMPOSER_')) and k not in ['PHPRC','PHP_INI_SCAN_DIR'] and k.upper() not in ['HTTP_PROXY','HTTPS_PROXY','ALL_PROXY']}
    env.update(COMPOSER_DISABLE_NETWORK='1',COMPOSER_NO_INTERACTION='1',COMPOSER_HOME=str(ROOT/'var/composer-home'),COMPOSER_CACHE_DIR=str(ROOT/'var/composer-cache'))
    return env
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package',required=True,help='Accepted sosecurity-1.0.0.zip')
    parser.add_argument('--php',default='php',help='PHP7.2 CLI executable')
    parser.add_argument('--composer',required=True,help='Composer PHP script/PHAR path')
    args=parser.parse_args()
    package=pathlib.Path(args.package).resolve();composer=pathlib.Path(args.composer).resolve()
    found=shutil.which(args.php);assert found,'PHP executable unavailable'
    php=pathlib.Path(found).resolve();assert composer.is_file(),'Composer script unavailable'
    assert digest(package)==PACKAGE_SHA256,'Package SHA256 mismatch: do not install'
    assert not any((ROOT/n).exists() for n in ['var','vendor','composer.lock','public/legacy-login.php']),'Fresh directory required; keep old state, do not delete it to retry'
    profile=json.loads(subprocess.check_output([str(php),'-r','echo json_encode(["version"=>PHP_VERSION,"extensions"=>get_loaded_extensions()]);']).decode())
    assert profile['version'].startswith('7.2.'),'This example is explicitly PHP7.2'
    assert all(n in profile['extensions'] for n in ['json','hash','session']),'Requires json/hash/session'
    os.umask(0o077)
    var=ROOT/'var';var.mkdir(mode=0o700)
    assert stat.S_IMODE(var.stat().st_mode)==0o700,'Use a native POSIX/WSL directory; Windows-mounted paths may not enforce 0700'
    for n in ['state','sessions','package']:(var/n).mkdir(mode=0o700)
    with zipfile.ZipFile(package) as z:
        names=[i.filename for i in z.infolist() if not i.is_dir()]
        assert len(names)==len(set(names))==780
        for i in z.infolist():
            p=pathlib.PurePosixPath(i.filename)
            assert not p.is_absolute() and '..' not in p.parts and not stat.S_ISLNK(i.external_attr>>16),'Unsafe ZIP member'
        z.extractall(var/'package')
    command=[str(php),str(composer),'install','--no-plugins','--no-scripts','--no-interaction','--no-progress']
    with (var/'install.log').open('x') as log:
        completed=subprocess.run(command,cwd=str(ROOT),env=environment(),stdout=log,stderr=subprocess.STDOUT,timeout=120)
    assert completed.returncode==0,'Installation failed; inspect private var/install.log; do not resume unknown operations'
    installed=ROOT/'vendor/sohophp/sosecurity';assert not installed.is_symlink()
    for n in names:assert digest(installed/n)==digest(var/'package'/n),n
    runtime={n:digest(installed/n) for n in names if n.startswith(('src/','resources/sql/'))};assert len(runtime)==367
    lock=json.loads((ROOT/'composer.lock').read_text());assert len(lock['packages'])==1 and lock['packages'][0]['version']=='1.0.0'
    adapter=installed/'examples/legacy-login.php';shutil.copyfile(adapter,ROOT/'public/legacy-login.php')
    password=secrets.token_urlsafe(18)
    hashed=subprocess.check_output([str(php),'-r','$password=stream_get_contents(STDIN); echo password_hash($password,PASSWORD_BCRYPT,["cost"=>10]);'],input=password.encode()).decode()
    config={'php':str(php),'username':'demo','password_hash':hashed,'state':str(var/'state'),'sessions':str(var/'sessions'),'https':False}
    (var/'config.json').write_text(json.dumps(config,indent=2)+'\n')
    (var/'demo-login.txt').write_text('username=demo\npassword='+password+'\n')
    manifest={'package_commit':PACKAGE_COMMIT,'package_sha256':PACKAGE_SHA256,'php':profile['version'],'installed_version':'1.0.0','installed_non_symlink':True,'all_780_members_match':True,'runtime_files':len(runtime),'runtime_manifest':runtime,'legacy_adapter_sha256':digest(adapter),'composer_lock_sha256':digest(ROOT/'composer.lock'),'install_exit':completed.returncode,'E_enabled':False}
    (var/'installation.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print('PASS installed pinned ZIP: 780 files, 367 runtime files; PHP '+profile['version']+'; offline, no plugins/scripts, no symlink')
    print('Local demo credentials: var/demo-login.txt (private, never commit or publish)')
    print('Start: python3 serve.py --port 8080')
if __name__=='__main__':main()

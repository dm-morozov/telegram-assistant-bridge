"""Bounded own-project cleanup: routes first, container stops despite reload failure."""
import argparse,json,os,re,subprocess
PROJECT='telegram-assistant-bridge-synthetic'
NAMES=('telegram-bridge-synthetic-https.conf','telegram-bridge-synthetic-loopback.conf')
def command(args): return subprocess.run(args,check=True,text=True,capture_output=True,timeout=20).stdout
def cleanup(container_id,image_id,run=command,enabled='/etc/nginx/sites-enabled',available='/etc/nginx/sites-available'):
    if not re.fullmatch(r'[a-f0-9]{64}',container_id) or not re.fullmatch(r'sha256:[a-f0-9]{64}',image_id): raise ValueError('Explicit own identity required')
    errors=[];removed=False;stopped=False
    try:
        for name in NAMES:
            path=os.path.join(enabled,name);expected=os.path.join(available,name)
            if os.path.lexists(path):
                if not os.path.islink(path) or os.readlink(path)!=expected: errors.append('Unexpected route object');continue
                os.unlink(path);removed=True
        if removed:
            try: run(['nginx','-t']);run(['systemctl','reload','nginx'])
            except Exception: errors.append('Route reload failed')
    finally:
        try: run(['systemctl','stop',PROJECT+'-jwks.service'])
        except Exception: errors.append('Helper stop needs verification')
        try:
            own=json.loads(run(['docker','inspect',container_id]))[0]
            if own.get('Id')!=container_id or own.get('Image')!=image_id or own.get('Config',{}).get('Labels',{}).get('com.docker.compose.project')!=PROJECT: raise ValueError()
            run(['docker','stop','--time','5',container_id]);stopped=True
        except Exception: errors.append('Container stop needs verification')
    return {'routesDisabled':all(not os.path.lexists(os.path.join(enabled,n)) for n in NAMES),'containerStopped':stopped,'errors':errors}
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--container-id',required=True);p.add_argument('--image-id',required=True);a=p.parse_args()
    import fcntl
    with open('/srv/projects/'+PROJECT+'/.cleanup.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX);result=cleanup(a.container_id,a.image_id)
    print(json.dumps(result))
    if result['errors'] or not result['routesDisabled'] or not result['containerStopped']: raise SystemExit(1)
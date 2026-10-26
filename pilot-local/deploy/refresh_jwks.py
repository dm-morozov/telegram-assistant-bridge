"""One fixed HTTPS public-JWKS refresh. No OAuth credentials or external dependencies."""
import argparse, base64, json, os, re, ssl, tempfile, time
from urllib.parse import urlsplit
from urllib.request import build_opener, ProxyHandler, HTTPSHandler, HTTPRedirectHandler, Request
MAX_BYTES=65536
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): raise ValueError('Redirect denied')
def source(issuer,uri):
    i,j=urlsplit(issuer),urlsplit(uri)
    if any(u.scheme!='https' or not u.hostname or u.username or u.password or u.query or u.fragment or u.hostname in ('localhost','127.0.0.1','::1') for u in (i,j)) or i.netloc!=j.netloc or j.path!='/.well-known/jwks.json': raise ValueError()
def public_keys(value):
    if not isinstance(value,dict) or set(value)!= {'keys'} or not isinstance(value['keys'],list) or not 1<=len(value['keys'])<=8: raise ValueError()
    result=[];seen=set()
    for k in value['keys']:
        if not isinstance(k,dict) or set(k)-{'kty','kid','alg','use','n','e','x5c','x5t','x5t#S256','key_ops'} or k.get('kty')!='RSA' or k.get('alg')!='RS256' or k.get('use')!='sig' or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}',k.get('kid','')) or k['kid'] in seen: raise ValueError()
        seen.add(k['kid']);numbers={}
        for field in ('n','e'):
            text=k.get(field,'')
            if not isinstance(text,str) or not re.fullmatch(r'[A-Za-z0-9_-]+',text): raise ValueError()
            data=base64.urlsafe_b64decode(text+'='*((-len(text))%4))
            if not data or data[0]==0 or base64.urlsafe_b64encode(data).decode().rstrip('=')!=text: raise ValueError()
            numbers[field]=(data,int.from_bytes(data,'big'))
        if not 2048<=numbers['n'][1].bit_length()<=8192 or len(numbers['e'][0])>8 or numbers['e'][1]<3 or numbers['e'][1]%2!=1: raise ValueError()
        if 'key_ops' in k and k['key_ops']!=['verify']: raise ValueError()
        if 'x5c' in k and (not isinstance(k['x5c'],list) or len(k['x5c'])>5 or any(not isinstance(v,str) or len(v)>8192 or not re.fullmatch(r'[A-Za-z0-9+/=]+',v) for v in k['x5c'])): raise ValueError()
        for field in ('x5t','x5t#S256'):
            if field in k and (not isinstance(k[field],str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}',k[field])): raise ValueError()
        result.append({field:k[field] for field in ('kty','kid','alg','use','n','e')})
    return {'keys':result}
def refresh(issuer,uri,path,opener=None):
    temporary=None
    try:
        source(issuer,uri)
        parent=os.path.dirname(path)
        if not os.path.isabs(path) or os.path.islink(parent) or not os.path.isdir(parent): raise ValueError()
        client=opener or build_opener(ProxyHandler({}),HTTPSHandler(context=ssl.create_default_context()),NoRedirect())
        req=Request(uri,headers={'Accept':'application/json'},method='GET')
        with client.open(req,timeout=3) as response:
            if response.status!=200 or response.geturl()!=uri or response.headers.get_content_type() not in ('application/json','application/jwk-set+json') or int(response.headers.get('Content-Length','0'))>MAX_BYTES: raise ValueError()
            data=response.read(MAX_BYTES+1)
            if len(data)>MAX_BYTES: raise ValueError()
            keys=public_keys(json.loads(data))
        snapshot={'schemaVersion':1,'issuer':issuer,'uri':uri,'fetchedAt':int(time.time()*1000),'jwks':keys}
        encoded=json.dumps(snapshot,separators=(',',':')).encode()
        if len(encoded)>MAX_BYTES: raise ValueError()
        fd,temporary=tempfile.mkstemp(prefix='.jwks-',suffix='.tmp',dir=parent)
        with os.fdopen(fd,'wb') as output: output.write(encoded)
        os.chmod(temporary,0o644);os.replace(temporary,path);temporary=None
    except Exception: raise RuntimeError('Public JWKS refresh failed') from None
    finally:
        if temporary: os.unlink(temporary)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--issuer',required=True);p.add_argument('--jwks-url',required=True);p.add_argument('--snapshot',required=True);a=p.parse_args()
    try: refresh(a.issuer,a.jwks_url,a.snapshot)
    except Exception: raise SystemExit('Public JWKS refresh failed')
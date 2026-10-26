import base64,io,json,os,tempfile,unittest
from email.message import Message
from unittest.mock import Mock
from refresh_jwks import refresh,public_keys,source,NoRedirect
from trial_stop import cleanup,PROJECT,NAMES
ISSUER='https://issuer.invalid/';URI=ISSUER+'.well-known/jwks.json'
def key(): return {'kty':'RSA','alg':'RS256','use':'sig','kid':'synthetic','n':base64.urlsafe_b64encode(b'\x80'+b'\x11'*255).decode().rstrip('='),'e':'AQAB'}
class Response:
    def __init__(self,body=None,status=200,uri=URI,mime='application/json'):
        self.status=status;self.uri=uri;self.headers=Message();self.headers['Content-Type']=mime;self.stream=io.BytesIO(body if body is not None else json.dumps({'keys':[key()]}).encode())
    def geturl(self): return self.uri
    def read(self,size): return self.stream.read(size)
    def __enter__(self): return self
    def __exit__(self,*a): return False
class Helpers(unittest.TestCase):
    def test_exact_public_key_fetch_and_atomic_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            path=os.path.join(directory,'jwks.snapshot.json');opener=Mock();opener.open.return_value=Response();refresh(ISSUER,URI,path,opener)
            request=opener.open.call_args.args[0];self.assertEqual(request.full_url,URI);self.assertEqual(request.get_method(),'GET');self.assertEqual(opener.open.call_args.kwargs,{'timeout':3});self.assertIsNone(request.get_header('Authorization'));self.assertIsNone(request.get_header('Cookie'));self.assertIsNone(request.data)
            original=open(path,'rb').read();value=json.loads(original);self.assertEqual(value['jwks'],{'keys':[key()]});self.assertEqual(set(os.listdir(directory)),{'jwks.snapshot.json'})
            for response in [Response(b'x'*65537),Response(b'{bad'),Response(status=302),Response(uri='https://other.invalid/'),Response(mime='text/plain'),Response(json.dumps({'keys':[{**key(),'d':'private-fixture-rejected'}]}).encode())]:
                opener.open.return_value=response
                with self.assertRaisesRegex(RuntimeError,'Public JWKS refresh failed'): refresh(ISSUER,URI,path,opener)
                self.assertEqual(open(path,'rb').read(),original);self.assertEqual(set(os.listdir(directory)),{'jwks.snapshot.json'})
            opener.open.side_effect=OSError('outage')
            with self.assertRaises(RuntimeError):refresh(ISSUER,URI,path,opener)
            self.assertEqual(open(path,'rb').read(),original)
    def test_public_shape_size_origin_and_redirect_guards(self):
        for value in [{'keys':[]},{'keys':[key(),key()]},{'keys':[{**key(),'alg':'HS256'}]},{'keys':[{**key(),'e':'Ag'}]},{'keys':[{**key(),'n':'AQAB'}]},{'keys':[{**key(),'jku':'https://other.invalid'}]}]:
            with self.assertRaises(ValueError):public_keys(value)
        for uri in ['http://issuer.invalid/.well-known/jwks.json','https://other.invalid/.well-known/jwks.json',URI+'?extra=true','https://issuer.invalid/other']:
            with self.assertRaises(ValueError):source(ISSUER,uri)
        with self.assertRaises(ValueError):NoRedirect().redirect_request(None,None,None,None,None,None)
    def test_routes_off_before_stop_even_when_nginx_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            enabled=os.path.join(directory,'enabled');available=os.path.join(directory,'available');os.mkdir(enabled);os.mkdir(available)
            for name in NAMES:os.symlink(os.path.join(available,name),os.path.join(enabled,name))
            calls=[];container='a'*64;image='sha256:'+'b'*64
            def run(args):
                calls.append(args)
                if args==['nginx','-t']:raise RuntimeError('synthetic test failure')
                if args[:2]==['docker','inspect']:return json.dumps([{'Id':container,'Image':image,'Config':{'Labels':{'com.docker.compose.project':PROJECT}}}])
                if args[:2]==['docker','stop']:self.assertEqual(os.listdir(enabled),[])
                return ''
            result=cleanup(container,image,run,enabled,available);self.assertTrue(result['routesDisabled']);self.assertTrue(result['containerStopped']);self.assertIn('Route reload failed',result['errors']);self.assertNotIn(['systemctl','reload','nginx'],calls);self.assertIn(['docker','stop','--time','5',container],calls)
            calls.clear()
            def wrong(args):
                calls.append(args)
                if args[:2]==['docker','inspect']:return json.dumps([{'Id':container,'Image':image,'Config':{'Labels':{'com.docker.compose.project':'neighbor'}}}])
                return ''
            result=cleanup(container,image,wrong,enabled,available);self.assertFalse(result['containerStopped']);self.assertFalse(any(c[:2]==['docker','stop'] for c in calls))
if __name__=='__main__':unittest.main()
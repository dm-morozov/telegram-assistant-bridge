"""Strict, bounded TLS readiness. No credentials, bodies or identities in diagnostics."""
import argparse, hashlib, http.client, json, re, socket, ssl, time

class ProbeFailure(Exception):
    def __init__(self, kind, certificate=None):
        self.kind = kind
        self.certificate = certificate
        super().__init__(kind)

class StrictConnection(http.client.HTTPSConnection):
    def __init__(self, host, target, timeout, fingerprint):
        super().__init__(host, timeout=timeout, context=ssl.create_default_context())
        self.target = target
        self.expected_fingerprint = fingerprint

    def connect(self):
        raw = socket.create_connection((self.target, 443), timeout=self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
            actual = hashlib.sha256(self.sock.getpeercert(binary_form=True)).hexdigest()
            if actual != self.expected_fingerprint:
                san = [v for k, v in self.sock.getpeercert().get('subjectAltName', ()) if k == 'DNS']
                raise ProbeFailure('leaf_mismatch', {'san': san, 'fingerprint': actual})
        except BaseException:
            raw.close()
            if self.sock is not None:
                self.sock.close()
            raise

def strict_probe(stage, *, host, path, issuer, fingerprint, until, clock=time.time):
    target = '127.0.0.1' if stage == 'loopback' else host
    def get(p):
        remaining = until - clock()
        if remaining <= 0:
            raise ProbeFailure('timeout')
        c = StrictConnection(host, target, min(2, remaining), fingerprint)
        try:
            c.request('GET', p, headers={'Host': host, 'Connection': 'close'})
            r = c.getresponse()
            body = r.read(16385)
            if len(body) > 16384:
                raise ProbeFailure('response_too_large')
            return r.status, body
        except ssl.SSLCertVerificationError:
            # An unverified connection is never opened to extract a certificate.
            raise ProbeFailure('tls_verification') from None
        except (TimeoutError, socket.timeout):
            raise ProbeFailure('timeout') from None
        except (OSError, http.client.HTTPException):
            raise ProbeFailure('transport') from None
        finally:
            c.close()
    status, _ = get(path)
    if status != 401:
        raise ProbeFailure('wrong_mcp_status')
    status, body = get('/.well-known/oauth-protected-resource' + path)
    if status != 200:
        raise ProbeFailure('wrong_prm_status')
    try:
        prm = json.loads(body)
        if prm['resource'] != 'https://' + host + path: raise ValueError()
        if prm['authorization_servers'] != [issuer]: raise ValueError()
        if prm['scopes_supported'] != ['messages:read', 'drafts:create']: raise ValueError()
    except (ValueError, KeyError, TypeError, AssertionError):
        raise ProbeFailure('wrong_prm') from None

def wait_ready(probe, *, deadline, budget=10, clock=time.time, sleep=time.sleep, rollback=lambda: None):
    # Reserve ten seconds for the caller's existing rollback. Never move deadline.
    until = min(clock() + budget, deadline - 10)
    diagnostics = []
    try:
        for stage in ('loopback', 'public'):
            while True:
                if clock() >= until:
                    raise ProbeFailure('timeout')
                try:
                    probe(stage, until)
                    if clock() >= until:
                        raise ProbeFailure('timeout')
                    break
                except ProbeFailure as e:
                    record = {'stage': stage, 'error': e.kind}
                    if e.certificate is not None:
                        record['certificate'] = e.certificate
                    if len(diagnostics) < 25:
                        diagnostics.append(record)
                    if e.kind not in ('leaf_mismatch', 'tls_verification', 'transport', 'timeout'):
                        raise
                    sleep(max(0, min(.25, until - clock())))
        return {'ready': True, 'diagnostics': diagnostics}
    except Exception:
        rollback()
        return {'ready': False, 'diagnostics': diagnostics}

def main():
    p = argparse.ArgumentParser()
    for name in ('host', 'resource-path', 'issuer', 'fingerprint'):
        p.add_argument('--' + name, required=True)
    p.add_argument('--deadline-epoch', type=int, required=True)
    a = p.parse_args()
    fingerprint = a.fingerprint.replace(':', '').lower()
    if not re.fullmatch(r'[a-f0-9]{64}', fingerprint):
        p.error('Expected SHA256 fingerprint required')
    if not re.fullmatch(r'[a-z0-9.-]+', a.host) or not re.fullmatch(r'/[a-zA-Z0-9/_-]+', a.resource_path):
        p.error('Canonical host and resource path required')
    result = wait_ready(lambda stage, until: strict_probe(stage, host=a.host, path=a.resource_path, issuer=a.issuer, fingerprint=fingerprint, until=until), deadline=a.deadline_epoch)
    print(json.dumps(result))
    return 0 if result['ready'] else 1

if __name__ == '__main__':
    raise SystemExit(main())

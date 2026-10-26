import importlib.util, pathlib, ssl, unittest
from unittest.mock import patch, MagicMock
spec = importlib.util.spec_from_file_location('tls_readiness', pathlib.Path(__file__).with_name('tls_readiness.py'))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

class Clock:
    def __init__(self): self.now = 100
    def time(self): return self.now
    def sleep(self, n): self.now += n

class ReadinessTests(unittest.TestCase):
    def run_wait(self, outcomes, deadline=700):
        clock = Clock(); calls = []; rollback = []
        def probe(stage, until):
            calls.append(stage)
            if outcomes:
                value = outcomes.pop(0)
                if value: raise m.ProbeFailure(value)
        result = m.wait_ready(probe, deadline=deadline, clock=clock.time, sleep=clock.sleep, rollback=lambda: rollback.append(True))
        return result, calls, rollback, clock

    def test_transient_mismatch_then_valid(self):
        result, calls, rollback, _ = self.run_wait(['leaf_mismatch', None, None])
        self.assertTrue(result['ready']); self.assertEqual(calls, ['loopback', 'loopback', 'public']); self.assertFalse(rollback)

    def test_persistent_mismatch_rolls_back_once(self):
        result, calls, rollback, clock = self.run_wait(['leaf_mismatch'] * 100)
        self.assertFalse(result['ready']); self.assertEqual(rollback, [True]); self.assertLessEqual(clock.now, 110); self.assertNotIn('public', calls)

    def test_public_stage_required(self):
        result, calls, rollback, _ = self.run_wait([None] + ['tls_verification'] * 100)
        self.assertFalse(result['ready']); self.assertIn('public', calls); self.assertEqual(rollback, [True])

    def test_timeout_rolls_back(self):
        result, _, rollback, _ = self.run_wait(['timeout'] * 100)
        self.assertFalse(result['ready']); self.assertEqual(rollback, [True])

    def test_wrong_status_and_prm_roll_back(self):
        for kind in ('wrong_mcp_status', 'wrong_prm_status', 'wrong_prm'):
            with self.subTest(kind=kind):
                result, calls, rollback, _ = self.run_wait([kind])
                self.assertFalse(result['ready']); self.assertEqual(calls, ['loopback']); self.assertEqual(rollback, [True])

    def test_deadline_is_never_extended(self):
        result, calls, rollback, clock = self.run_wait(['transport'] * 100, deadline=111)
        self.assertFalse(result['ready']); self.assertLessEqual(clock.now, 101); self.assertEqual(rollback, [True])

    def test_expired_deadline_does_not_probe(self):
        result, calls, rollback, _ = self.run_wait([], deadline=105)
        self.assertFalse(result['ready']); self.assertEqual(calls, []); self.assertEqual(rollback, [True])

    def test_diagnostics_exclude_exception_text(self):
        clock = Clock()
        def probe(stage, until): raise RuntimeError('secret-token-cookie-code-state-email')
        result = m.wait_ready(probe, deadline=700, clock=clock.time, sleep=clock.sleep)
        self.assertNotIn('secret', str(result)); self.assertFalse(result['ready'])

    def test_sni_and_strict_context(self):
        ctx = ssl.create_default_context(); sock = MagicMock(); sock.getpeercert.return_value = b'certificate'
        import hashlib
        with patch.object(m.ssl, 'create_default_context', return_value=ctx), patch.object(m.socket, 'create_connection') as create, patch.object(ssl.SSLContext, 'wrap_socket', return_value=sock) as wrap:
            c = m.StrictConnection('bridge.example', '127.0.0.1', 1, hashlib.sha256(b'certificate').hexdigest()); c.connect()
            self.assertTrue(ctx.check_hostname); self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
            create.assert_called_once_with(('127.0.0.1', 443), timeout=1)
            self.assertEqual(wrap.call_args.kwargs['server_hostname'], 'bridge.example')

    def test_wrong_fingerprint_rejects_before_http(self):
        sock = MagicMock(); sock.getpeercert.side_effect = [b'certificate', {'subjectAltName': [('DNS', 'bridge.example')]}]
        with patch.object(m.socket, 'create_connection'), patch.object(ssl.SSLContext, 'wrap_socket', return_value=sock):
            c = m.StrictConnection('bridge.example', '127.0.0.1', 1, '0' * 64)
            with self.assertRaises(m.ProbeFailure) as raised: c.connect()
            self.assertEqual(raised.exception.kind, 'leaf_mismatch'); self.assertEqual(set(raised.exception.certificate), {'san', 'fingerprint'}); sock.sendall.assert_not_called()

    def probe_responses(self, responses, fingerprint='0'*64):
        connections = []
        def factory(*args):
            c = MagicMock(); r = MagicMock(); r.status, body = responses[len(connections)]
            r.read.return_value = body; c.getresponse.return_value = r; connections.append(c); return c
        with patch.object(m, 'StrictConnection', side_effect=factory):
            m.strict_probe('loopback', host='bridge.example', path='/private-mcp', issuer='https://issuer.invalid/', fingerprint=fingerprint, until=110, clock=lambda: 100)
        return connections

    def test_real_probe_requires_exact_prm_and_status(self):
        import json
        body = json.dumps({'resource':'https://bridge.example/private-mcp','authorization_servers':['https://issuer.invalid/'],'scopes_supported':['messages:read','drafts:create']}).encode()
        c = self.probe_responses([(401,b''),(200,body)])
        self.assertEqual(len(c),2)
        self.assertEqual(c[0].request.call_args.args, ('GET','/private-mcp'))
        self.assertEqual(set(c[0].request.call_args.kwargs['headers']), {'Host','Connection'})
        self.assertTrue(all(x.close.called for x in c))

    def test_real_probe_wrong_status(self):
        with self.assertRaises(m.ProbeFailure) as e: self.probe_responses([(200,b'private text not logged')])
        self.assertEqual(e.exception.kind, 'wrong_mcp_status'); self.assertNotIn('private text', str(e.exception))

    def test_real_probe_wrong_prm(self):
        for body in (b'invalid-json-sensitive-text', b'{}', b'{"resource":"https://other.invalid"}'):
            with self.assertRaises(m.ProbeFailure) as e: self.probe_responses([(401,b''),(200,body)])
            self.assertEqual(e.exception.kind, 'wrong_prm'); self.assertNotIn('sensitive', str(e.exception))

    def test_real_probe_wrong_prm_status(self):
        with self.assertRaises(m.ProbeFailure) as e: self.probe_responses([(401,b''),(404,b'')])
        self.assertEqual(e.exception.kind, 'wrong_prm_status')

    def test_real_probe_rejects_oversized_response(self):
        with self.assertRaises(m.ProbeFailure) as e: self.probe_responses([(401,b'x'*16385)])
        self.assertEqual(e.exception.kind, 'response_too_large')

if __name__ == '__main__': unittest.main()

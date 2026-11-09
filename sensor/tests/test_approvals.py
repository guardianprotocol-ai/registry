"""Authorization tests use synthetic identities and no Kubernetes API."""
import concurrent.futures
import os
import sqlite3
import sys
import tempfile
import time
import unittest
from contextlib import closing

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from guardian_sensor.approvals import ApprovalStore
from guardian_sensor.sensor import Sensor, pump
from unittest.mock import patch
import io
import json


class Approvals(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, 'approvals.db')
        ApprovalStore.initialize(self.path)
        self.store = ApprovalStore(self.path)
        self.request = ['user:test', 'agent:test', 'management-cluster:test',
                        'capi_mutate', {'verb': 'delete', 'group': 'cluster.x-k8s.io',
                        'resource': 'machines', 'namespace': 'tenant-a',
                        'name': 'worker', 'uid': 'object-uid', 'resourceVersion': '42'}]

    def grant(self):
        return self.store.grant(*self.request, approver='operator:test', expires=time.time()+60)

    def test_exact_request_and_restart_replay(self):
        aid = self.grant()
        self.assertTrue(self.store.consume(aid, *self.request))
        self.assertFalse(ApprovalStore(self.path).consume(aid, *self.request))

    def test_identity_audience_tool_and_every_argument_are_bound(self):
        aid = self.grant()
        for index in range(4):
            changed = list(self.request)
            changed[index] += ':forged'
            self.assertFalse(self.store.consume(aid, *changed))
        for key in self.request[4]:
            changed = list(self.request)
            changed[4] = dict(changed[4], **{key: 'different'})
            self.assertFalse(self.store.consume(aid, *changed))
        self.assertTrue(self.store.consume(aid, *self.request))

    def test_expiration_and_revocation(self):
        aid = self.grant()
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('UPDATE approvals SET expires=0 WHERE id=?', (aid,))
        self.assertFalse(self.store.consume(aid, *self.request))
        aid = self.grant()
        self.store.revoke(aid)
        self.assertFalse(self.store.consume(aid, *self.request))

    def test_concurrent_requests_only_one_wins(self):
        aid = self.grant()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: ApprovalStore(self.path).consume(aid, *self.request), range(8)))
        self.assertEqual(sum(results), 1)

    def test_audit_failure_rolls_back_consumption(self):
        aid = self.grant()
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('DROP TABLE audit')
        with self.assertRaises(sqlite3.Error):
            self.store.consume(aid, *self.request)
        with closing(sqlite3.connect(self.path)) as db, db:
            self.assertIsNone(db.execute('SELECT consumed FROM approvals').fetchone()[0])

    def sensor(self):
        return Sensor({
            'mode': 'monitor',
            'pins_path': os.path.join(self.tmp.name, 'pins.json'),
            'canaries_path': os.path.join(self.tmp.name, 'canaries.json'),
            'path_canaries_path': os.path.join(self.tmp.name, 'paths.json'),
            'breach_policy_path': os.path.join(self.tmp.name, 'breach.json'),
            'evidence_path': os.path.join(self.tmp.name, 'evidence.jsonl'),
            'delegated_approval': dict(zip(
                ['subject', 'agent', 'audience', 'tool'], self.request[:4]), database=self.path)})

    def message(self, aid):
        return {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {
            'name': self.request[3], 'arguments': self.request[4],
            '_meta': {'guardian/approval_id': aid}}}

    def test_proxy_requires_approval_even_clean_and_monitoring(self):
        sensor = self.sensor()
        self.assertTrue(sensor.inspect_request(self.message('invented'))['result']['isError'])
        aid = self.grant()
        self.assertIsNone(sensor.inspect_request(self.message(aid)))
        self.assertTrue(sensor.inspect_request(self.message(aid))['result']['isError'])

    def test_proxy_rejects_alternate_tool_and_store_failure(self):
        sensor = self.sensor()
        aid = self.grant()
        msg = self.message(aid)
        msg['params']['name'] = 'Bash'
        self.assertTrue(sensor.inspect_request(msg)['result']['isError'])
        with patch.object(ApprovalStore, 'consume', side_effect=sqlite3.OperationalError):
            self.assertTrue(sensor.inspect_request(self.message(aid))['result']['isError'])

    def test_proxy_fault_never_forwards(self):
        destination = io.StringIO()
        def broken(msg):
            raise RuntimeError('simulated failure')
        pump(io.StringIO('{"method":"tools/call"}\n'), destination, broken, self.sensor())
        self.assertEqual(destination.getvalue(), '')

    def test_pipe_forwards_approved_call_once_and_replies_to_replay(self):
        sensor = self.sensor()
        message = json.dumps(self.message(self.grant())) + '\n'
        destination, replies = io.StringIO(), io.StringIO()
        pump(io.StringIO(message + message), destination,
             sensor.inspect_request, sensor, reply_to=replies)
        self.assertEqual(destination.getvalue(), message)
        self.assertTrue(json.loads(replies.getvalue())['result']['isError'])

    def test_malformed_input_cannot_reach_backend(self):
        sensor = self.sensor()
        destination = io.StringIO()
        pump(io.StringIO('not-json\n'), destination, sensor.inspect_request,
             sensor, reply_to=io.StringIO())
        self.assertEqual(destination.getvalue(), '')


if __name__ == '__main__':
    unittest.main()

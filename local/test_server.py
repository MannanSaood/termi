import datetime
import hashlib
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
import unittest

from serve import Snapshot, handler


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / 'pool').mkdir()
        self.payload = b'isolated transport fixture\n' * 100
        self.package = self.root / 'pool/example_1%3A2_aarch64.deb'
        self.package.write_bytes(self.payload)
        report = dict(schema=1, channel='main', packages=1, profile='test-only', complete_catalog=False,
            valid_until=(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).isoformat(),
            routes={'/apt/main/pool/example_1%3A2_aarch64.deb': dict(relative='pool/' + self.package.name,
                     bytes=len(self.payload), sha256=hashlib.sha256(self.payload).hexdigest())})
        self.report = self.root / 'verified.json'
        self.report.write_text(json.dumps(report))
        self.pin = hashlib.sha256(self.report.read_bytes()).hexdigest()
        self.snapshot = Snapshot(self.root, self.report, self.pin)
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), handler(self.snapshot))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temp.cleanup()

    def request(self, path, method='GET', headers=None):
        connection = HTTPConnection('127.0.0.1', self.server.server_port, timeout=3)
        connection.request(method, path, headers=headers or {})
        response = connection.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        connection.close()
        return result

    def test_get_head_ranges_and_epoch_filenames(self):
        for path in ['/apt/main/pool/example_1%3A2_aarch64.deb', '/apt/main/pool/example_1%253A2_aarch64.deb']:
            self.assertEqual(self.payload, self.request(path)[2])
        path = '/apt/main/pool/example_1%253A2_aarch64.deb'
        status, headers, body = self.request(path, 'HEAD')
        self.assertEqual((200, b''), (status, body))
        self.assertEqual(len(self.payload), int(headers['Content-Length']))
        status, headers, body = self.request(path, headers={'Range': 'bytes=11-39'})
        self.assertEqual((206, self.payload[11:40]), (status, body))
        self.assertEqual(416, self.request(path, headers={'Range': 'bytes=999999-'})[0])

    def test_only_explicit_files_are_reachable(self):
        (self.root / 'secret.txt').write_text('test-only unrelated fixture')
        for path in ['/pool/', '/apt/main/pool/', '/secret.txt', '/apt/main/../../secret.txt',
                     '/apt/main/%2e%2e/%2e%2e/secret.txt', '/apt/main/pool/example_1%3A2_aarch64.deb?x=1']:
            self.assertEqual(404, self.request(path)[0])
        self.assertEqual(501, self.request('/', 'POST')[0])
        self.assertEqual(False, json.loads(self.request('/healthz')[2])['complete_catalog'])

    def test_changed_snapshot_expiry_and_report_tampering_fail_closed(self):
        self.package.write_bytes(b'changed')
        self.assertEqual(503, self.request('/apt/main/pool/example_1%3A2_aarch64.deb')[0])
        self.snapshot.expires = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=1)
        self.assertEqual(503, self.request('/healthz')[0])
        self.report.write_bytes(self.report.read_bytes() + b' ')
        with self.assertRaisesRegex(ValueError, 'explicit pin'):
            Snapshot(self.root, self.report, self.pin)


if __name__ == '__main__':
    unittest.main()

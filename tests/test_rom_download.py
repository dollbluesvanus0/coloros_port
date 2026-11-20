"""Exercise the shared aria2 entry point against a local HTTP server."""
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[1]
DATA = b'0123456789abcdef' * (2 * 1024 * 1024 + 1)


@unittest.skipUnless(shutil.which('aria2c') and shutil.which('bash'), 'aria2c and bash are required')
class RomDownloadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                if self.headers.get('userId') != 'oplus-ota|16000020' or self.headers.get('User-Agent') != 'okhttp/5.3.2':
                    self.send_error(403)
                    return
                if self.path == '/redirect':
                    self.send_response(302)
                    self.send_header('Location', '/rom.zip')
                    self.send_header('Content-Length', '0')
                    self.end_headers()
                    return
                if self.path != '/rom.zip':
                    self.send_error(404)
                    return
                start, end = 0, len(DATA) - 1
                part = re.fullmatch(r'bytes=(\d+)-(\d*)', self.headers.get('Range', ''))
                if part:
                    start = int(part[1])
                    end = int(part[2]) if part[2] else end
                if start >= len(DATA):
                    self.send_error(416)
                    return
                self.send_response(206 if part else 200)
                if part:
                    self.send_header('Content-Range', f'bytes {start}-{end}/{len(DATA)}')
                self.send_header('Content-Encoding', 'UTF-8')
                self.send_header('Content-Length', str(end - start + 1))
                self.end_headers()
                try:
                    self.wfile.write(DATA[start:end+1])
                except (BrokenPipeError, ConnectionResetError):
                    pass
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def invoke(self, endpoint, destination):
        env = dict(os.environ)
        # Only local fixture traffic is excluded from the inherited proxy.
        env['no_proxy'] = env.get('no_proxy', '') + ',127.0.0.1'
        env['NO_PROXY'] = env.get('NO_PROXY', '') + ',127.0.0.1'
        return subprocess.run(
            ['bash', '-c', 'source "$1/functions.sh"; port_download_rom "$2" "$3"',
             'test', str(ROOT), f'http://127.0.0.1:{self.server.server_port}/{endpoint}', str(destination)],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30,
        )

    def test_redirect_ranges_and_cdn_charset(self):
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / 'rom.zip'
            result = self.invoke('redirect', destination)
            self.assertEqual(result.returncode, 0, result.stdout.decode(errors='replace'))
            self.assertEqual(hashlib.sha256(destination.read_bytes()).digest(), hashlib.sha256(DATA).digest())
            self.assertFalse(Path(str(destination) + '.aria2').exists())

    def test_http_error_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            self.assertNotEqual(self.invoke('missing', Path(temp) / 'rom.zip').returncode, 0)

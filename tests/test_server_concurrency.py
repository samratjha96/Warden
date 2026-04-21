import threading
import unittest
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler

import server


class SlowAndFastHandler(BaseHTTPRequestHandler):
    slow_started = threading.Event()
    release_slow = threading.Event()

    def log_message(self, format, *args):
        return

    def do_GET(self):
        if self.path == "/slow":
            type(self).slow_started.set()
            type(self).release_slow.wait(timeout=5)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"slow")
            return

        if self.path == "/fast":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"fast")
            return

        self.send_response(404)
        self.end_headers()


class ServerConcurrencyTests(unittest.TestCase):
    def request_path(self, port: int, path: str) -> str:
        conn = HTTPConnection("127.0.0.1", port, timeout=2)
        conn.request("GET", path)
        response = conn.getresponse()
        body = response.read().decode("utf-8")
        conn.close()
        return body

    def test_http_server_class_serves_fast_request_while_slow_request_blocks(self):
        SlowAndFastHandler.slow_started = threading.Event()
        SlowAndFastHandler.release_slow = threading.Event()

        httpd = server.HTTP_SERVER_CLASS(("127.0.0.1", 0), SlowAndFastHandler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()

        slow_result = {}

        def run_slow():
            slow_result["body"] = self.request_path(httpd.server_port, "/slow")

        slow_thread = threading.Thread(target=run_slow, daemon=True)
        slow_thread.start()
        self.assertTrue(SlowAndFastHandler.slow_started.wait(timeout=1))

        try:
            fast_body = self.request_path(httpd.server_port, "/fast")
        finally:
            SlowAndFastHandler.release_slow.set()
            slow_thread.join(timeout=5)
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=5)

        self.assertEqual(fast_body, "fast")
        self.assertEqual(slow_result["body"], "slow")


if __name__ == "__main__":
    unittest.main()

import json
import unittest
from io import BytesIO
from unittest.mock import patch

import server
from server import Handler, SimpleHTTPRequestHandler, count_active_jobs


class ServerSafetyTests(unittest.TestCase):
    def test_count_active_jobs_counts_pending_and_processing_only(self):
        queue = {
            "jobs": [
                {"id": "1", "status": "pending"},
                {"id": "2", "status": "processing"},
                {"id": "3", "status": "done"},
                {"id": "4", "status": "failed"},
            ]
        }
        self.assertEqual(count_active_jobs(queue), 2)

    def test_cors_does_not_allow_every_origin_by_default(self):
        with (
            patch.object(Handler, "send_header") as send_header,
            patch.object(SimpleHTTPRequestHandler, "end_headers"),
        ):
            handler = Handler.__new__(Handler)
            handler.path = "/api/reports"

            Handler.end_headers(handler)

        sent_headers = [call.args for call in send_header.call_args_list]
        self.assertNotIn(("Access-Control-Allow-Origin", "*"), sent_headers)

    def test_regeneration_rejects_oversized_steering(self):
        class TestHandler(Handler):
            def __init__(self):
                self.path = "/api/reports/owner-repo-abcd1234/regenerate"
                self.headers = {"Content-Length": "20017"}
                self.rfile = BytesIO(
                    json.dumps({"steering": "x" * 20001}).encode("utf-8")
                )
                self.status = None
                self.payload = None

            def respond(self, status, payload, headers=None):
                self.status = status
                self.payload = payload

        handler = TestHandler()
        Handler.do_POST(handler)

        self.assertEqual(handler.status, 413)
        self.assertEqual(handler.payload["code"], "steering_too_large")

    def test_api_token_accepts_bearer_header_when_configured(self):
        handler = Handler.__new__(Handler)
        handler.headers = {"Authorization": "Bearer expected-token"}

        with patch.object(server, "WARDEN_API_TOKEN", "expected-token"):
            self.assertTrue(Handler.is_authorized(handler))

    def test_report_json_paths_are_runtime_json_requests(self):
        handler = Handler.__new__(Handler)
        handler.path = "/data/reports/owner-repo-abcd1234.json"

        self.assertTrue(Handler.is_runtime_json_request(handler))


if __name__ == "__main__":
    unittest.main()

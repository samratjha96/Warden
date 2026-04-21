import json
import threading
import unittest
from http.client import HTTPConnection
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import server


class ServerSubmitApiTests(unittest.TestCase):
    def start_server(self):
        httpd = server.HTTP_SERVER_CLASS(("127.0.0.1", 0), server.Handler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        return httpd, thread

    def post_submit(self, port: int, body: dict) -> tuple[int, dict]:
        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request(
            "POST",
            "/api/submit",
            body=json.dumps(body),
            headers={"Content-Type": "application/json"},
        )
        response = conn.getresponse()
        payload = json.loads(response.read().decode("utf-8"))
        conn.close()
        return response.status, payload

    def test_submit_enqueues_job_and_triggers_worker(self):
        with TemporaryDirectory() as tmp:
            queue_file = Path(tmp) / "jobs.json"
            queue_file.write_text(json.dumps({"jobs": []}))

            with (
                patch.object(server, "QUEUE_FILE", str(queue_file)),
                patch.object(server, "QUEUE_LOCK_FILE", str(queue_file) + ".lock"),
                patch.object(server, "MAX_ACTIVE_JOBS", 1),
                patch.object(server.SUBMISSION_LIMITER, "allow", return_value=(True, "", 0)),
                patch.object(server, "trigger_worker_for_job", return_value=(True, "")),
            ):
                httpd, thread = self.start_server()
                try:
                    status, payload = self.post_submit(
                        httpd.server_port,
                        {
                            "url": "https://github.com/openai/openai-python",
                            "ecosystem": "auto",
                            "severity": "low",
                            "depth": "shallow",
                        },
                    )
                finally:
                    httpd.shutdown()
                    httpd.server_close()
                    thread.join(timeout=5)

            self.assertEqual(status, 201)
            self.assertTrue(payload["autoWorkerTriggered"])
            self.assertEqual(payload["job"]["owner"], "openai")
            self.assertEqual(payload["job"]["repo"], "openai-python")

            queue = json.loads(queue_file.read_text())
            self.assertEqual(len(queue["jobs"]), 1)
            self.assertEqual(queue["jobs"][0]["id"], payload["job"]["id"])

    def test_submit_rejects_duplicate_repo(self):
        existing = {
            "jobs": [
                {
                    "id": "openai-openai-python-existing",
                    "url": "https://github.com/openai/openai-python",
                    "provider": "github",
                    "owner": "openai",
                    "repo": "openai-python",
                    "status": "pending",
                    "submitted": "2026-04-21T00:00:00Z",
                    "options": {
                        "ecosystem": "auto",
                        "severity": "low",
                        "depth": "shallow",
                    },
                }
            ]
        }

        with TemporaryDirectory() as tmp:
            queue_file = Path(tmp) / "jobs.json"
            queue_file.write_text(json.dumps(existing))

            with (
                patch.object(server, "QUEUE_FILE", str(queue_file)),
                patch.object(server, "QUEUE_LOCK_FILE", str(queue_file) + ".lock"),
                patch.object(server, "MAX_ACTIVE_JOBS", 1),
                patch.object(server.SUBMISSION_LIMITER, "allow", return_value=(True, "", 0)),
                patch.object(server, "trigger_worker_for_job", return_value=(True, "")),
            ):
                httpd, thread = self.start_server()
                try:
                    status, payload = self.post_submit(
                        httpd.server_port,
                        {"url": "https://github.com/openai/openai-python"},
                    )
                finally:
                    httpd.shutdown()
                    httpd.server_close()
                    thread.join(timeout=5)

            self.assertEqual(status, 409)
            self.assertEqual(payload["code"], "duplicate_queue_entry")


if __name__ == "__main__":
    unittest.main()

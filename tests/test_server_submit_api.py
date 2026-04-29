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

    def get_json(self, port: int, path: str) -> tuple[int, dict]:
        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", path)
        response = conn.getresponse()
        payload = json.loads(response.read().decode("utf-8"))
        conn.close()
        return response.status, payload

    def test_health_endpoint_reports_ok(self):
        httpd, thread = self.start_server()
        try:
            status, payload = self.get_json(httpd.server_port, "/api/healthz")
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=5)

        self.assertEqual(status, 200)
        self.assertEqual(payload, {"ok": True})

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

    def test_job_status_reports_pending_job(self):
        with TemporaryDirectory() as tmp:
            queue_file = Path(tmp) / "jobs.json"
            queue_file.write_text(
                json.dumps(
                    {
                        "jobs": [
                            {
                                "id": "openai-openai-python-12345678",
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
                )
            )

            with (
                patch.object(server, "QUEUE_FILE", str(queue_file)),
                patch.object(server, "QUEUE_LOCK_FILE", str(queue_file) + ".lock"),
            ):
                httpd, thread = self.start_server()
                try:
                    status, payload = self.get_json(
                        httpd.server_port,
                        "/api/jobs/openai-openai-python-12345678",
                    )
                finally:
                    httpd.shutdown()
                    httpd.server_close()
                    thread.join(timeout=5)

            self.assertEqual(status, 200)
            self.assertEqual(payload["jobId"], "openai-openai-python-12345678")
            self.assertEqual(payload["status"], "pending")
            self.assertEqual(payload["repository"]["owner"], "openai")
            self.assertEqual(payload["links"]["self"], "/api/jobs/openai-openai-python-12345678")
            self.assertEqual(payload["links"]["report"], "/api/reports/openai-openai-python-12345678")

    def test_job_status_reports_completed_job_from_report(self):
        with TemporaryDirectory() as tmp:
            queue_file = Path(tmp) / "jobs.json"
            reports_dir = Path(tmp) / "reports"
            reports_dir.mkdir()
            queue_file.write_text(json.dumps({"jobs": []}))
            (reports_dir / "openai-openai-python-12345678.json").write_text(
                json.dumps(
                    {
                        "id": "openai-openai-python-12345678",
                        "url": "https://github.com/openai/openai-python",
                        "provider": "github",
                        "owner": "openai",
                        "repo": "openai-python",
                        "analyzed": "2026-04-21",
                        "verdict": "APPROVE",
                        "risk": "low",
                        "keyFinding": "No critical issues found.",
                        "content": "# Report",
                    }
                )
            )

            with (
                patch.object(server, "QUEUE_FILE", str(queue_file)),
                patch.object(server, "QUEUE_LOCK_FILE", str(queue_file) + ".lock"),
                patch.object(server, "REPORTS_DIR", str(reports_dir)),
            ):
                httpd, thread = self.start_server()
                try:
                    status, payload = self.get_json(
                        httpd.server_port,
                        "/api/jobs/openai-openai-python-12345678",
                    )
                finally:
                    httpd.shutdown()
                    httpd.server_close()
                    thread.join(timeout=5)

            self.assertEqual(status, 200)
            self.assertEqual(payload["status"], "succeeded")
            self.assertEqual(payload["reportId"], "openai-openai-python-12345678")
            self.assertEqual(payload["completedAt"], "2026-04-21")

    def test_get_report_returns_full_report(self):
        with TemporaryDirectory() as tmp:
            reports_dir = Path(tmp) / "reports"
            reports_dir.mkdir()
            (reports_dir / "openai-openai-python-12345678.json").write_text(
                json.dumps(
                    {
                        "id": "openai-openai-python-12345678",
                        "url": "https://github.com/openai/openai-python",
                        "provider": "github",
                        "owner": "openai",
                        "repo": "openai-python",
                        "analyzed": "2026-04-21",
                        "verdict": "APPROVE",
                        "risk": "low",
                        "keyFinding": "No critical issues found.",
                        "content": "# Report",
                    }
                )
            )

            with patch.object(server, "REPORTS_DIR", str(reports_dir)):
                httpd, thread = self.start_server()
                try:
                    status, payload = self.get_json(
                        httpd.server_port,
                        "/api/reports/openai-openai-python-12345678",
                    )
                finally:
                    httpd.shutdown()
                    httpd.server_close()
                    thread.join(timeout=5)

            self.assertEqual(status, 200)
            self.assertEqual(payload["report"]["id"], "openai-openai-python-12345678")
            self.assertEqual(payload["report"]["content"], "# Report")

    def test_search_reports_filters_by_repository(self):
        with TemporaryDirectory() as tmp:
            reports_dir = Path(tmp) / "reports"
            index_file = reports_dir / "index.json"
            reports_dir.mkdir()
            index_file.write_text(
                json.dumps(
                    {
                        "reports": [
                            {
                                "id": "openai-openai-python-12345678",
                                "provider": "github",
                                "owner": "openai",
                                "repo": "openai-python",
                                "analyzed": "2026-04-21",
                            },
                            {
                                "id": "pallets-flask-12345678",
                                "provider": "github",
                                "owner": "pallets",
                                "repo": "flask",
                                "analyzed": "2026-04-20",
                            },
                        ]
                    }
                )
            )

            with patch.object(server, "REPORTS_INDEX_FILE", str(index_file)):
                httpd, thread = self.start_server()
                try:
                    status, payload = self.get_json(
                        httpd.server_port,
                        "/api/reports?provider=github&owner=openai&repo=openai-python",
                    )
                finally:
                    httpd.shutdown()
                    httpd.server_close()
                    thread.join(timeout=5)

            self.assertEqual(status, 200)
            self.assertEqual(payload["count"], 1)
            self.assertEqual(payload["reports"][0]["id"], "openai-openai-python-12345678")


if __name__ == "__main__":
    unittest.main()

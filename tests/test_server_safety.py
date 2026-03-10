import unittest

from server import count_active_jobs


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


if __name__ == "__main__":
    unittest.main()

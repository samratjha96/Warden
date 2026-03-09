import unittest

from queue_ops import enqueue_job, remove_job


class QueueOpsTests(unittest.TestCase):
    def test_enqueue_job_blocks_duplicate_repo(self):
        queue = {
            "jobs": [
                {
                    "id": "chalk-chalk-aaaa1111",
                    "provider": "github",
                    "owner": "chalk",
                    "repo": "chalk",
                    "status": "pending",
                }
            ]
        }
        duplicate = {
            "id": "chalk-chalk-bbbb2222",
            "provider": "github",
            "owner": "Chalk",
            "repo": "chalk",
            "status": "pending",
        }

        with self.assertRaises(ValueError):
            enqueue_job(queue, duplicate)

    def test_enqueue_job_accepts_different_repo(self):
        queue = {"jobs": []}
        job = {
            "id": "chalk-ansi-styles-cccc3333",
            "provider": "github",
            "owner": "chalk",
            "repo": "ansi-styles",
            "status": "pending",
        }
        enqueue_job(queue, job)
        self.assertEqual(len(queue["jobs"]), 1)
        self.assertEqual(queue["jobs"][0]["id"], job["id"])

    def test_remove_job_deletes_item_by_id(self):
        queue = {
            "jobs": [
                {"id": "a", "provider": "github", "owner": "x", "repo": "one"},
                {"id": "b", "provider": "github", "owner": "x", "repo": "two"},
            ]
        }
        removed = remove_job(queue, "a")
        self.assertTrue(removed)
        self.assertEqual([j["id"] for j in queue["jobs"]], ["b"])

    def test_remove_job_returns_false_for_missing_id(self):
        queue = {"jobs": [{"id": "only", "provider": "github", "owner": "x", "repo": "one"}]}
        self.assertFalse(remove_job(queue, "missing"))
        self.assertEqual(len(queue["jobs"]), 1)


if __name__ == "__main__":
    unittest.main()

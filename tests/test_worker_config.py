import unittest

from worker_config import WorkerConfig, load_worker_config


class WorkerConfigTests(unittest.TestCase):
    def test_load_worker_config_reads_required_environment_values(self):
        config = load_worker_config(
            {
                "WARDEN_MODEL": "example-model",
                "OPENAI_COMPATIBLE_ENDPOINT": "https://example.test/v1",
                "NVIDIA_API_KEY": "secret-key",
            }
        )

        self.assertEqual(
            config,
            WorkerConfig(
                model="example-model",
                base_url="https://example.test/v1",
                api_key="secret-key",
            ),
        )

    def test_load_worker_config_requires_all_values(self):
        with self.assertRaises(KeyError):
            load_worker_config({"WARDEN_MODEL": "example-model"})


if __name__ == "__main__":
    unittest.main()

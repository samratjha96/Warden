import unittest
from pathlib import Path
from unittest.mock import patch

from env_bootstrap import load_project_dotenv


class EnvBootstrapTests(unittest.TestCase):
    def test_load_project_dotenv_returns_false_when_python_dotenv_is_missing(self):
        with patch("importlib.import_module", side_effect=ModuleNotFoundError):
            self.assertFalse(load_project_dotenv(Path("/tmp/.env")))

    def test_load_project_dotenv_loads_dotenv_when_available(self):
        calls = []

        class FakeDotenv:
            @staticmethod
            def load_dotenv(path):
                calls.append(path)

        with patch("importlib.import_module", return_value=FakeDotenv):
            self.assertTrue(load_project_dotenv(Path("/tmp/.env")))

        self.assertEqual(calls, [Path("/tmp/.env")])


if __name__ == "__main__":
    unittest.main()

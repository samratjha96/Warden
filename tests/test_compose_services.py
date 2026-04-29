import json
from pathlib import Path
import shutil
import subprocess
import unittest


class ComposeServicesTests(unittest.TestCase):
    def test_compose_declares_trending_service(self):
        docker = shutil.which("docker") or "/usr/local/bin/docker"
        if not Path(docker).exists():
            self.skipTest("Docker is not available")

        result = subprocess.run(
            [docker, "compose", "config", "--format", "json"],
            check=True,
            capture_output=True,
            text=True,
        )
        config = json.loads(result.stdout)
        trending = config["services"]["trending"]

        self.assertEqual(trending["command"], ["trending"])
        self.assertEqual(trending["environment"]["TRENDING_MAX_REPOS"], "10")
        self.assertEqual(trending["environment"]["TRENDING_DEDUPE_DAYS"], "30")
        self.assertTrue(
            any(volume["target"] == "/app/site/data" for volume in trending["volumes"])
        )


if __name__ == "__main__":
    unittest.main()

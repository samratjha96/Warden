import unittest
from pathlib import Path


class ApiResponseParsingTests(unittest.TestCase):
    def test_app_uses_defensive_api_response_parser(self):
        script = Path("site/js/app.js").read_text()
        self.assertIn("function parseApiResponse", script)
        self.assertIn("content-type", script.lower())
        self.assertIn("Unexpected non-JSON response", script)

    def test_delete_paths_use_shared_parser(self):
        script = Path("site/js/app.js").read_text()
        self.assertIn("return parseApiResponse(r);", script)


if __name__ == "__main__":
    unittest.main()

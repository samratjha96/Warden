import unittest

from repo_url import parse_repo_url


class ParseRepoUrlTests(unittest.TestCase):
    def test_parses_github_url_without_scheme(self):
        parsed = parse_repo_url("github.com/facebook/react")
        self.assertEqual(parsed["provider"], "github")
        self.assertEqual(parsed["owner"], "facebook")
        self.assertEqual(parsed["repo"], "react")
        self.assertEqual(parsed["url"], "https://github.com/facebook/react")

    def test_strips_only_git_suffix(self):
        parsed = parse_repo_url("https://github.com/pallets/flask.git")
        self.assertEqual(parsed["repo"], "flask")

        parsed_no_suffix = parse_repo_url("https://github.com/facebook/react")
        self.assertEqual(parsed_no_suffix["repo"], "react")

    def test_rejects_invalid_url(self):
        with self.assertRaises(ValueError):
            parse_repo_url("https://example.com/not-a-supported-host/repo")


if __name__ == "__main__":
    unittest.main()

"""Network-free checks for release handoff and recovery after partial API writes."""

import base64
import subprocess
import unittest
from unittest.mock import patch

from bump_homebrew import FORMULA, SOURCE, bump, update_formula


CHECKSUM = "b" * 64
FORMULA_TEXT = f'''class GithitsScan < Formula
  url "{SOURCE}v0.3.0.tar.gz"
  sha256 "{'a' * 64}"

  bottle do
    root_url "https://github.com/githits-com/homebrew-tap/releases/download/githits-scan-0.3.0"
    sha256 cellar: :any_skip_relocation, arm64_sequoia: "{'c' * 64}"
  end

  depends_on "rust" => :build
end
'''


class BumpTests(unittest.TestCase):
    def setUp(self):
        self.main = FORMULA_TEXT
        self.branch = None
        self.prs = []
        self.writes = []
        self.fail_update = False
        self.fail_pr = False
        self.mock = patch("bump_homebrew.api", side_effect=self.api)
        self.mock.start()
        self.addCleanup(self.mock.stop)

    def api(self, endpoint, method="GET", **payload):
        if method != "GET":
            self.writes.append((endpoint, payload))
        if endpoint == "git/ref/heads/main":
            return {"object": {"sha": "main-commit"}}
        if endpoint.startswith(f"contents/{FORMULA}?ref="):
            text = self.main if endpoint.endswith("=main-commit") else self.branch
            return {"sha": "blob-sha", "content": base64.b64encode(text.encode()).decode()}
        if endpoint.startswith("pulls?"):
            return self.prs
        if endpoint.startswith("git/matching-refs/"):
            return [{"ref": "refs/heads/homebrew/githits-scan-v0.4.0"}] if self.branch else []
        if endpoint == "git/refs":
            self.assertEqual(payload["sha"], "main-commit")
            self.branch = self.main
            return {}
        if endpoint == f"contents/{FORMULA}":
            if self.fail_update:
                raise subprocess.CalledProcessError(1, "gh")
            self.branch = base64.b64decode(payload["content"]).decode()
            return {}
        if endpoint == "pulls":
            if self.fail_pr:
                raise subprocess.CalledProcessError(1, "gh")
            self.prs = [{"state": "open", "html_url": "https://github.com/githits-com/homebrew-tap/pull/1"}]
            return self.prs[0]
        self.fail(f"Unexpected API call: {endpoint}")

    def test_new_release_opens_one_pr_and_removes_prior_bottles(self):
        bump("v0.4.0", CHECKSUM)
        self.assertIn(f'{SOURCE}v0.4.0.tar.gz', self.branch)
        self.assertIn(f'  sha256 "{CHECKSUM}"', self.branch)
        self.assertNotIn("bottle do", self.branch)
        self.assertIn('  depends_on "rust" => :build', self.branch)
        self.assertEqual(len(self.writes), 3)
        bump("v0.4.0", CHECKSUM)
        self.assertEqual(len(self.writes), 3)

    def test_current_or_newer_main_does_not_change_the_tap(self):
        for version in ("v0.3.0", "v0.2.0"):
            with self.subTest(version=version):
                bump(version, CHECKSUM)
        self.assertEqual(self.writes, [])

    def test_closed_or_merged_pr_is_not_recreated(self):
        self.prs = [{"state": "closed", "html_url": "https://github.com/githits-com/homebrew-tap/pull/1"}]
        bump("v0.4.0", CHECKSUM)
        self.assertEqual(self.writes, [])

    def test_resume_after_branch_creation_before_formula_update(self):
        self.fail_update = True
        with self.assertRaises(subprocess.CalledProcessError):
            bump("v0.4.0", CHECKSUM)
        self.fail_update = False
        self.writes.clear()
        bump("v0.4.0", CHECKSUM)
        self.assertEqual([endpoint for endpoint, _ in self.writes], [f"contents/{FORMULA}", "pulls"])

    def test_resume_after_formula_update_before_pr_creation(self):
        self.fail_pr = True
        with self.assertRaises(subprocess.CalledProcessError):
            bump("v0.4.0", CHECKSUM)
        self.fail_pr = False
        self.writes.clear()
        bump("v0.4.0", CHECKSUM)
        self.assertEqual([endpoint for endpoint, _ in self.writes], ["pulls"])

    def test_bad_metadata_and_unrecognized_formula_fail_before_writes(self):
        for tag, checksum in (("v0.4.0-rc.1", CHECKSUM), ("v0.4.0", "invalid")):
            with self.subTest(tag=tag, checksum=checksum), self.assertRaises(ValueError):
                bump(tag, checksum)
        self.main = FORMULA_TEXT.replace('  sha256 "', '  invalid "', 1)
        with self.assertRaises(ValueError):
            bump("v0.4.0", CHECKSUM)
        self.main = FORMULA_TEXT.replace(SOURCE, "https://example.com/")
        with self.assertRaises(ValueError):
            bump("v0.4.0", CHECKSUM)
        self.assertEqual(self.writes, [])

    def test_formula_without_bottles_can_be_bumped(self):
        source_only = update_formula(FORMULA_TEXT, "v0.4.0", CHECKSUM)
        updated = update_formula(source_only, "v0.5.0", "d" * 64)
        self.assertIn(f'{SOURCE}v0.5.0.tar.gz', updated)


if __name__ == "__main__":
    unittest.main()

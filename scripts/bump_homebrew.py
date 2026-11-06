"""Open one tap formula PR per published stable release, using gh's environment token."""

import base64
import json
import re
import subprocess
import sys


REPOSITORY = "githits-com/homebrew-tap"
API = f"repos/{REPOSITORY}"
FORMULA = "Formula/githits-scan.rb"
SOURCE = "https://github.com/githits-com/githits-scan/archive/refs/tags/"


def api(endpoint, method="GET", **payload):
    """Keep authentication in GH_TOKEN, and JSON request bodies on stdin."""
    result = subprocess.run(
        ["gh", "api", "--method", method, f"{API}/{endpoint}", "--input", "-"],
        input=json.dumps(payload), text=True, stdout=subprocess.PIPE, check=True,
    )
    return json.loads(result.stdout)


def formula_at(ref):
    """Read a formula at a commit or branch and retain its blob SHA for the update."""
    blob = api(f"contents/{FORMULA}?ref={ref}")
    return blob, base64.b64decode(blob["content"]).decode()


def update_formula(formula, tag, checksum):
    """Replace source metadata and discard bottles built for the prior source."""
    formula, urls = re.subn(r'^  url ".*"$', f'  url "{SOURCE}{tag}.tar.gz"', formula, flags=re.M)
    formula, sums = re.subn(r'^  sha256 "[0-9a-f]{64}"$', f'  sha256 "{checksum}"', formula, flags=re.M)
    if (urls, sums) != (1, 1):
        raise ValueError("Expected exactly one source URL and SHA-256 in the formula")
    return re.sub(r"\n  bottle do\n.*?^  end\n", "", formula, flags=re.M | re.S)


def bump(tag, checksum):
    """Resume partial updates without force-pushing or opening duplicate PRs."""
    if not re.fullmatch(r"v\d+\.\d+\.\d+", tag) or not re.fullmatch(r"[0-9a-f]{64}", checksum):
        raise ValueError("Expected a stable vX.Y.Z tag and SHA-256")
    branch = f"homebrew/githits-scan-{tag}"
    base = api("git/ref/heads/main")["object"]["sha"]
    _, formula = formula_at(base)
    current = re.search(r'^  url "' + re.escape(SOURCE) + r'v(\d+)\.(\d+)\.(\d+)\.tar.gz"$', formula, re.M)
    if current is None:
        raise ValueError("Unrecognized tap source URL")
    if tuple(map(int, current.groups())) >= tuple(map(int, tag[1:].split("."))):
        print("Tap already contains this release or a newer version.")
        return
    prs = api(f"pulls?state=all&head=githits-com:{branch}")
    if prs:
        print(f"Release PR already exists ({prs[0]['state']}): {prs[0]['html_url']}")
        return
    # Validate the source formula before creating any branch.
    update_formula(formula, tag, checksum)
    refs = api(f"git/matching-refs/heads/{branch}")
    if not any(ref["ref"] == f"refs/heads/{branch}" for ref in refs):
        api("git/refs", "POST", ref=f"refs/heads/{branch}", sha=base)
    blob, formula = formula_at(branch)
    updated = update_formula(formula, tag, checksum)
    if updated != formula:
        api(f"contents/{FORMULA}", "PUT", branch=branch, sha=blob["sha"],
            message=f"chore: bump githits-scan to {tag}\n\nTrack the published source release; rebuild bottles in tap CI.",
            content=base64.b64encode(updated.encode()).decode())
    pr = api("pulls", "POST", base="main", head=branch,
             title=f"githits-scan {tag}",
             body=f"Update to the published [Scan {tag}](https://github.com/githits-com/githits-scan/releases/tag/{tag}) source.\n\n"
                  "Review the formula and bottle CI, then apply `pr-pull` to publish bottles and merge.\n"
                  "Do not merge with GitHub's merge button before bottle publication.")
    print(pr["html_url"])


if __name__ == "__main__":
    bump(*sys.argv[1:])

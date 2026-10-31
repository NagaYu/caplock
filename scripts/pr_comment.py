#!/usr/bin/env python3
"""Post or update the CapLock PR comment (standard library + the gh CLI).

  pr_comment.py --repo OWNER/NAME --pr NUMBER --body-file caplock.md [--dry-run]

One comment per pull request: an existing comment whose body starts with
MARKER is updated in place, otherwise a new one is created (no double posts).

The pure parts (marker detection, body/payload construction, parsing gh
output, choosing create vs update) are separated from the network part
(``run_gh``) so they can be unit-tested offline. Authentication comes from
gh itself (GH_TOKEN in Actions); no token is read, logged or passed here.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

MARKER = "<!-- caplock -->"
MAX_BODY = 65000  # GitHub's comment limit is 65536 characters
TRUNCATION_NOTE = "\n\n_…truncated: the full report is in the job summary and the SARIF upload._\n"


# --------------------------------------------------------------------------- pure


def has_marker(body: object) -> bool:
    """A CapLock comment starts with the marker (anchored, so quoted text elsewhere does not match)."""
    return isinstance(body, str) and body.lstrip().startswith(MARKER)


def build_body(markdown: str) -> str:
    body = f"{MARKER}\n{markdown}"
    if len(body) > MAX_BODY:
        body = body[: MAX_BODY - len(TRUNCATION_NOTE)] + TRUNCATION_NOTE
    return body


def build_payload(markdown: str) -> dict:
    return {"body": build_body(markdown)}


def parse_paginated(text: str) -> list[dict]:
    """``gh api --paginate`` prints one JSON array per page back to back; flatten them."""
    dec = json.JSONDecoder()
    items: list[dict] = []
    i, n = 0, len(text)
    while i < n:
        while i < n and text[i].isspace():
            i += 1
        if i >= n:
            break
        value, i = dec.raw_decode(text, i)
        items.extend(value if isinstance(value, list) else [value])
    return items


def find_marker_comment(comments: list[dict]) -> dict | None:
    """The oldest comment carrying the marker (stable choice if duplicates ever exist)."""
    marked = [c for c in comments if has_marker(c.get("body")) and isinstance(c.get("id"), int)]
    return min(marked, key=lambda c: c["id"]) if marked else None


@dataclass
class Plan:
    method: str  # "POST" | "PATCH"
    endpoint: str
    payload: dict


def plan_request(repo: str, pr: int, comments: list[dict], markdown: str) -> Plan:
    existing = find_marker_comment(comments)
    payload = build_payload(markdown)
    if existing:
        return Plan("PATCH", f"repos/{repo}/issues/comments/{existing['id']}", payload)
    return Plan("POST", f"repos/{repo}/issues/{pr}/comments", payload)


def validate_target(repo: str, pr: str) -> tuple[str, int]:
    owner, sep, name = repo.partition("/")
    if not sep or not owner or not name or "/" in name or any(c.isspace() for c in repo):
        raise ValueError(f"--repo must be OWNER/NAME, got {repo!r}")
    if not str(pr).isdigit() or int(pr) <= 0:
        raise ValueError(f"--pr must be a positive integer, got {pr!r}")
    return repo, int(pr)


# --------------------------------------------------------------------------- network (gh)


def run_gh(args: list[str], stdin: str | None = None) -> str:
    r = subprocess.run(["gh", *args], input=stdin, capture_output=True, text=True, check=False)
    if r.returncode != 0:
        raise RuntimeError(f"gh {' '.join(args[:3])} failed (exit {r.returncode})")
    return r.stdout


def sync_comment(repo: str, pr: int, markdown: str, gh=run_gh) -> Plan:
    comments = parse_paginated(gh(["api", "--paginate", f"repos/{repo}/issues/{pr}/comments"]))
    plan = plan_request(repo, pr, comments, markdown)
    gh(["api", "-X", plan.method, plan.endpoint, "--input", "-"], stdin=json.dumps(plan.payload))
    return plan


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", required=True)
    ap.add_argument("--pr", required=True)
    ap.add_argument("--body-file", type=Path, required=True)
    ap.add_argument("--dry-run", action="store_true", help="print what would be sent; no network")
    args = ap.parse_args(argv)
    try:
        repo, pr = validate_target(args.repo, args.pr)
    except ValueError as e:
        print(f"pr_comment: {e}", file=sys.stderr)
        return 3
    markdown = args.body_file.read_text(encoding="utf-8")
    if args.dry_run:
        plan = plan_request(repo, pr, [], markdown)
        print(json.dumps({"method": plan.method, "endpoint": plan.endpoint, "bodyLength": len(plan.payload["body"])}))
        return 0
    try:
        plan = sync_comment(repo, pr, markdown)
    except (RuntimeError, OSError, json.JSONDecodeError) as e:
        print(f"pr_comment: {e}", file=sys.stderr)
        return 1
    print(f"pr_comment: {'updated' if plan.method == 'PATCH' else 'created'} CapLock comment on {repo}#{pr}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

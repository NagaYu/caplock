"""scripts/pr_comment.py: marker detection and payload construction (offline; gh is faked)."""

import json

import pytest

import pr_comment as pc


def test_marker_must_start_the_body():
    assert pc.has_marker("<!-- caplock -->\n## CapLock verify")
    assert pc.has_marker("  \n<!-- caplock -->\nx")
    assert not pc.has_marker("LGTM. <!-- caplock -->")  # quoted somewhere else
    assert not pc.has_marker("<!-- caplock-other -->")
    assert not pc.has_marker(None)


def test_body_has_marker_and_is_truncated_to_github_limit():
    body = pc.build_body("## CapLock verify\n")
    assert body.startswith(pc.MARKER + "\n") and pc.has_marker(body)
    long = pc.build_body("x" * 100_000)
    assert len(long) <= pc.MAX_BODY and long.endswith(pc.TRUNCATION_NOTE) and pc.has_marker(long)


def test_parse_paginated_concatenated_pages():
    text = '[{"id": 1, "body": "a"}]\n[{"id": 2, "body": "b"}, {"id": 3, "body": "c"}]\n'
    assert [c["id"] for c in pc.parse_paginated(text)] == [1, 2, 3]
    assert pc.parse_paginated("") == [] and pc.parse_paginated("[]") == []


def test_find_marker_comment_picks_oldest_marked():
    comments = [{"id": 9, "body": "hi"}, {"id": 7, "body": pc.MARKER + "\nold"},
                {"id": 8, "body": pc.MARKER + "\nnewer"}, {"id": 5, "body": "mention <!-- caplock -->"}]
    assert pc.find_marker_comment(comments)["id"] == 7
    assert pc.find_marker_comment([{"id": 1, "body": "x"}]) is None


def test_plan_updates_existing_comment():
    plan = pc.plan_request("o/r", 12, [{"id": 44, "body": pc.MARKER + "\nprev"}], "## new")
    assert (plan.method, plan.endpoint) == ("PATCH", "repos/o/r/issues/comments/44")
    assert plan.payload == {"body": pc.MARKER + "\n## new"}


def test_plan_creates_when_absent():
    plan = pc.plan_request("o/r", 12, [{"id": 1, "body": "unrelated"}], "## new")
    assert (plan.method, plan.endpoint) == ("POST", "repos/o/r/issues/12/comments")


@pytest.mark.parametrize("repo, pr", [("o/r", "0"), ("o", "1"), ("o/r/x", "1"), ("o/r", "1; rm"), ("o r/x", "1")])
def test_validate_target_rejects_bad_input(repo, pr):
    with pytest.raises(ValueError):
        pc.validate_target(repo, pr)


class FakeGh:
    def __init__(self, existing):
        self.calls = []
        self.existing = existing

    def __call__(self, args, stdin=None):
        self.calls.append((args, stdin))
        if args[:2] == ["api", "--paginate"]:
            return json.dumps(self.existing)
        return "{}"


def test_sync_twice_never_double_posts():
    gh = FakeGh([])
    first = pc.sync_comment("o/r", 3, "## report", gh=gh)
    assert first.method == "POST"
    posted = json.loads(gh.calls[-1][1])
    gh.existing = [{"id": 100, "body": posted["body"]}]
    second = pc.sync_comment("o/r", 3, "## report v2", gh=gh)
    assert (second.method, second.endpoint) == ("PATCH", "repos/o/r/issues/comments/100")
    assert gh.calls[-1][0] == ["api", "-X", "PATCH", "repos/o/r/issues/comments/100", "--input", "-"]


def test_dry_run_does_not_call_gh(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(pc, "run_gh", lambda *a, **k: pytest.fail("network call in dry run"))
    f = tmp_path / "r.md"
    f.write_text("## CapLock verify\n")
    assert pc.main(["--repo", "o/r", "--pr", "5", "--body-file", str(f), "--dry-run"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["method"] == "POST" and out["endpoint"] == "repos/o/r/issues/5/comments"

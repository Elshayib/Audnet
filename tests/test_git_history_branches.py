"""Additional branch-coverage tests for git_history defensive paths.

These target lines the main test_git_history.py does not exercise:
- GitPython-absent guard (_require_gitpython raises)
- _push_repo warning path when no remote is configured

NOTE: the bare-repo working-tree-None guards in save_config_snapshot /
rollback_config (git_history.py:255, :445) are NOT covered here. They are
currently unreachable: init_git_repo(bare=True) itself raises inside GitPython
before returning, so those guards are effectively dead code (see flagged bug).
"""

from pathlib import Path

import pytest

from audnet.exceptions import GitHistoryError
from audnet import git_history
from audnet.git_history import _push_repo, init_git_repo


class TestRequireGitPython:
    def test_raises_when_gitpython_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Simulate GitPython not being importable.
        monkeypatch.setattr(git_history, "gitpython", None)
        # Every public entrypoint goes through _require_gitpython().
        with pytest.raises(GitHistoryError, match="GitPython is not installed"):
            git_history.init_git_repo(Path("/tmp/should-not-be-created"))


class TestPushRepoWarning:
    def test_push_without_remote_logs_warning(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        import logging

        repo_path = tmp_path / "git-repo"
        repo = init_git_repo(repo_path)
        # No remote configured -> _push_repo should swallow the error and warn.
        with caplog.at_level(logging.WARNING, logger="audnet.git_history"):
            _push_repo(repo, "origin")
        assert any("Failed to push" in rec.message for rec in caplog.records)

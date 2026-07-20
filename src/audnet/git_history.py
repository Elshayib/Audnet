"""Git-backed device config history.

Stores full device running configs in a Git repository with timestamped commits,
provides diff viewing, and supports safe rollback to previous known-good configs.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from audnet.exceptions import GitHistoryError

logger = logging.getLogger(__name__)

try:
    import git as gitpython
    from git import InvalidGitRepositoryError, NoSuchPathError
    from git.exc import GitCommandError
except ImportError:
    gitpython = None  # type: ignore[assignment]

__all__ = [
    "GitHistoryError",
    "sanitize_config",
    "init_git_repo",
    "save_config_snapshot",
    "get_config_at",
    "get_config_history",
    "diff_configs",
    "rollback_config",
    "_DEFAULT_GIT_DIR",
]

_DEFAULT_GIT_DIR = Path.home() / ".net-audit" / "git-config-history"

# Patterns for lines that should never be committed to a public/non-encrypted repo.
# Start-of-line patterns: keyword must be the first word (after optional whitespace).
_SENSITIVE_LINE_RE = re.compile(
    r"""
    ^\s*(
        (?:enable\s+)?
        password
        |(?:enable\s+)?secret
        |key[\s-]+(?:string|hash)
        |snmp-server\s+community
        |ip\s+ospf\s+message-digest-key
        |isis\s+password
        |bgp\s+password
        |ntp\s+authkey
        |tacacs[\s-]key
        |radius[\s-]key
        |pre-shared-key
        |auth-key
        |priv-key
        |-----BEGIN\s.*PRIVATE\sKEY-----
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Mid-line patterns: sensitive keyword appears after a prefix (e.g. "username admin password ...").
# These match the keyword anywhere in the line, but require a word boundary before it
# to avoid false positives.
_SENSITIVE_MIDLINE_RE = re.compile(
    r"""
    (
        username\s+\S+\s+password
        |ip\s+ftp\s+password
        |tacacs-server\s+key
        |ntp\s+authentication-key
        |crypto\s+(?:isakmp|ike)\s+key
        |neighbor\s+\S+\s+(?:bgp\s+)?password
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


def sanitize_config(raw_config: str, device_name: str) -> str:
    """Redact sensitive lines from a raw device config before Git storage.

    Replaces lines containing passwords, keys, community strings, etc. with
    a redacted marker. The original config is not modified.

    Args:
        raw_config: The full running config text from a device.
        device_name: The device name (used in redaction markers).

    Returns:
        Sanitized config text safe for version control.
    """
    if not raw_config:
        return ""
    lines = raw_config.splitlines(keepends=True)
    sanitized: list[str] = []
    for line in lines:
        if _SENSITIVE_LINE_RE.search(line) or _SENSITIVE_MIDLINE_RE.search(line):
            sanitized.append(f"! [REDACTED by audnet — {device_name}]\n")
        else:
            sanitized.append(line)
    return "".join(sanitized)


def sanitize_config_to_file(raw_config: str, device_name: str, output_path: Path) -> None:
    """Sanitize a device config and write directly to a file.

    Processes the raw config line-by-line, writing each line to *output_path*
    immediately. This avoids holding both the raw and sanitized configs in
    memory simultaneously, reducing peak memory from O(2 × config_size) to
    O(config_size).

    Args:
        raw_config: The full running config text from a device.
        device_name: The device name (used in redaction markers).
        output_path: Path to write the sanitized config to.
    """
    if not raw_config:
        output_path.write_text("")
        return
    with open(output_path, "w") as fh:
        for line in raw_config.splitlines(keepends=True):
            if _SENSITIVE_LINE_RE.search(line) or _SENSITIVE_MIDLINE_RE.search(line):
                fh.write(f"! [REDACTED by audnet — {device_name}]\n")
            else:
                fh.write(line)


def _require_gitpython() -> None:
    """Raise GitHistoryError if GitPython is not installed."""
    if gitpython is None:
        raise GitHistoryError("GitPython is not installed. Install it with: pip install GitPython")


def init_git_repo(
    repo_path: Path | None = None,
    bare: bool = False,
) -> gitpython.Repo:
    """Initialize or open a Git repository for config history.

    If the repo already exists, it is opened as-is. If not, a new one is
    initialized with an initial empty commit.

    Args:
        repo_path: Path to the Git repo. Defaults to ~/.net-audit/git-config-history.
        bare: If True, create a bare repo (for remote/central storage).

    Returns:
        A GitPython Repo object.

    Raises:
        GitHistoryError: If GitPython is not installed or the path is invalid.
    """
    _require_gitpython()
    if repo_path is None:
        repo_path = _DEFAULT_GIT_DIR

    try:
        repo = gitpython.Repo(repo_path)
        logger.debug("Opened existing Git repo at %s", repo_path)
        return repo
    except (InvalidGitRepositoryError, NoSuchPathError):
        pass

    repo_path.mkdir(parents=True, exist_ok=True)
    repo = gitpython.Repo.init(repo_path, bare=bare)
    # Configure user identity even for bare repos (config lives in git_dir).
    _configure_repo(repo)
    if not bare:
        # Seed an initial commit so the repo has a valid HEAD. A bare repo has
        # no working tree, so no seed file/commit is created there.
        initial_file = repo_path / ".gitkeep"
        initial_file.touch()
        repo.index.add([str(initial_file.relative_to(repo_path))])
        repo.index.commit(
            "chore: initialize audnet Git config history repo",
            commit_date=_commit_dt(),
            author_date=_commit_dt(),
        )
    logger.info("Initialized new Git config history repo at %s", repo_path)
    return repo


def _configure_repo(repo: gitpython.Repo) -> None:
    """Set minimal git config for the repo if not already configured."""
    # Check repo-level config only (not global/system)
    git_dir = repo.git_dir
    if git_dir is None:
        has_name = False
        has_email = False
    else:
        repo_cfg_path = Path(git_dir) / "config"
        if repo_cfg_path.exists():
            import configparser

            parser = configparser.ConfigParser()
            parser.read(str(repo_cfg_path))
            has_name = parser.has_option("user", "name")
            has_email = parser.has_option("user", "email")
        else:
            has_name = False
            has_email = False

    config = repo.config_writer()
    try:
        if not has_name:
            config.set_value("user", "name", "audnet")
        if not has_email:
            config.set_value("user", "email", "audnet@localhost")
    finally:
        config.release()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _commit_dt() -> str:
    """Return current UTC datetime string for git commit authorship."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S %z")


def save_config_snapshot(
    device_configs: dict[str, str],
    history_dir: Path | None = None,
    push: bool = False,
    remote: str = "origin",
) -> str | None:
    """Commit device configs to the Git history repo.

    Each device gets its own file named ``<device_name>.cfg`` (lowercased,
    special chars replaced with ``-``). The file content is the sanitized
    running config.

    Args:
        device_configs: Mapping of ``device_name -> raw_running_config``.
        history_dir: Path to the Git repo. Defaults to ~/.net-audit/git-config-history.
        push: If True, attempt to push to ``remote`` after committing.
        remote: Remote name to push to (default: origin).

    Returns:
        The commit hexsha if a new commit was created, None if there were
        no changes to commit.

    Raises:
        GitHistoryError: If the Git operation fails.
    """
    _require_gitpython()
    repo = init_git_repo(history_dir)
    wt = repo.working_tree_dir
    if wt is None:
        raise GitHistoryError("Git repo has no working tree (bare repo?)")
    work_tree = Path(wt)

    for device_name, raw_config in device_configs.items():
        safe_name = re.sub(r"[^a-zA-Z0-9._-]", "-", device_name.lower())
        cfg_file = work_tree / f"{safe_name}.cfg"
        # Stream-sanitize directly to file instead of building full
        # sanitized string in memory alongside raw_config.
        sanitize_config_to_file(raw_config, device_name, cfg_file)
        repo.index.add([str(cfg_file.relative_to(work_tree))])

    if not repo.index.diff("HEAD") and not repo.untracked_files:
        logger.debug("No config changes to commit")
        return None

    commit_msg = _build_commit_message(device_configs)
    ts = _commit_dt()
    repo.index.commit(
        commit_msg,
        commit_date=ts,
        author_date=ts,
    )
    commit_sha = repo.head.commit.hexsha
    logger.info("Saved config snapshot: %s", commit_sha[:12])

    if push:
        _push_repo(repo, remote)

    return commit_sha


def _build_commit_message(device_configs: dict[str, str]) -> str:
    """Build a structured commit message for config snapshots."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    devices = ", ".join(sorted(device_configs.keys()))
    return (
        f"feat(config): snapshot device configs\n\n"
        f"Devices: {devices}\n"
        f"Timestamp: {ts}\n"
        f"Config count: {len(device_configs)}\n"
    )


def _push_repo(repo: gitpython.Repo, remote: str = "origin") -> None:
    """Push the current branch to the named remote."""
    try:
        remote_obj = repo.remote(remote)
        remote_obj.push()
        logger.info("Pushed config history to remote '%s'", remote)
    except (GitCommandError, ValueError) as exc:
        logger.warning(
            "Failed to push config history to remote '%s': %s. "
            "Config is stored locally; push manually when remote is configured.",
            remote,
            exc,
        )


def get_config_at(
    device_name: str,
    commit_ref: str = "HEAD",
    history_dir: Path | None = None,
) -> str | None:
    """Retrieve a device's config at a specific Git ref.

    Args:
        device_name: The device name.
        commit_ref: A git ref (SHA, tag, HEAD~N, etc.).
        history_dir: Path to the Git repo.

    Returns:
        The sanitized config text, or None if the device has no config
        at that ref.
    """
    _require_gitpython()
    repo = init_git_repo(history_dir)
    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "-", device_name.lower())
    cfg_rel = f"{safe_name}.cfg"

    try:
        commit = repo.commit(commit_ref)
        blob = commit.tree / cfg_rel
        data: bytes = blob.data_stream.read()
        return data.decode("utf-8")
    except (KeyError, GitCommandError):
        return None


def get_config_history(
    device_name: str,
    history_dir: Path | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Get the Git commit history for a specific device's config.

    Returns a list of dicts with keys: commit_sha, committed_ts, message, config.
    """
    _require_gitpython()
    repo = init_git_repo(history_dir)
    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "-", device_name.lower())
    cfg_rel = f"{safe_name}.cfg"

    results: list[dict[str, Any]] = []
    for commit in repo.iter_commits("HEAD", paths=[cfg_rel], max_count=limit):
        try:
            blob = commit.tree / cfg_rel
            config_text = blob.data_stream.read().decode("utf-8")
        except KeyError:
            config_text = ""
        committed_dt = datetime.fromtimestamp(commit.committed_date, tz=timezone.utc)
        results.append(
            {
                "commit_sha": commit.hexsha,
                "committed_at": committed_dt.isoformat(),
                "message": commit.message.strip(),
                "config": config_text,
            }
        )
    return results


def diff_configs(
    device_name: str,
    from_ref: str = "HEAD~1",
    to_ref: str = "HEAD",
    history_dir: Path | None = None,
) -> str:
    """Produce a unified diff between two config snapshots.

    Args:
        device_name: The device name.
        from_ref: The older git ref.
        to_ref: The newer git ref.
        history_dir: Path to the Git repo.

    Returns:
        Unified diff text (empty string if no changes).
    """
    _require_gitpython()
    repo = init_git_repo(history_dir)
    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "-", device_name.lower())
    cfg_rel = f"{safe_name}.cfg"

    commit_from = repo.commit(from_ref)
    commit_to = repo.commit(to_ref)

    diffs = commit_from.diff(
        commit_to,
        paths=[cfg_rel],
        create_patch=True,
    )
    parts: list[str] = []
    for d in diffs:
        if d.diff is None:
            patch = ""
        elif isinstance(d.diff, bytes):
            patch = d.diff.decode("utf-8", errors="replace")
        else:
            patch = d.diff
        parts.append(patch)
    return "\n".join(parts)


def rollback_config(
    device_name: str,
    commit_ref: str = "HEAD~1",
    history_dir: Path | None = None,
    push: bool = False,
    dry_run: bool = True,
) -> dict[str, Any]:
    """Restore a device's config from a previous Git commit.

    In dry-run mode (the default), returns the target config without
    writing it. In live mode, writes the config file and commits the
    restoration.

    Args:
        device_name: The device name.
        commit_ref: The git ref to roll back to.
        history_dir: Path to the Git repo.
        push: If True and not dry_run, push after committing.
        dry_run: If True, only return the target config without writing.

    Returns:
        A dict with keys: device_name, target_ref, target_sha, config, dry_run.
    """
    _require_gitpython()
    repo = init_git_repo(history_dir)
    wt = repo.working_tree_dir
    if wt is None:
        raise GitHistoryError("Git repo has no working tree (bare repo?)")
    work_tree = Path(wt)
    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "-", device_name.lower())
    cfg_file = work_tree / f"{safe_name}.cfg"

    target_config = get_config_at(device_name, commit_ref, history_dir=history_dir)
    if target_config is None:
        raise GitHistoryError(f"No config found for device '{device_name}' at ref '{commit_ref}'")

    target_commit = repo.commit(commit_ref)

    result: dict[str, Any] = {
        "device_name": device_name,
        "target_ref": commit_ref,
        "target_sha": target_commit.hexsha,
        "config": target_config,
        "dry_run": dry_run,
    }

    if dry_run:
        logger.info(
            "[dry-run] Would rollback %s to %s (%s)",
            device_name,
            commit_ref,
            target_commit.hexsha[:12],
        )
        return result

    # Write the restored config
    cfg_file.write_text(target_config)
    repo.index.add([str(cfg_file.relative_to(work_tree))])
    ts = _commit_dt()
    repo.index.commit(
        f"feat(config): rollback {device_name} to {commit_ref} ({target_commit.hexsha[:12]})\n\n"
        f"Rollback target: {commit_ref}\n"
        f"Target SHA: {target_commit.hexsha}\n",
        commit_date=ts,
        author_date=ts,
    )
    result["new_commit"] = repo.head.commit.hexsha
    logger.info(
        "Rolled back %s to %s, new commit: %s",
        device_name,
        commit_ref,
        repo.head.commit.hexsha[:12],
    )

    if push:
        _push_repo(repo, "origin")

    return result

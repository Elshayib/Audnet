"""Tests for the version module."""

import importlib

import audnet
from audnet import __version__


class TestVersion:
    def test_version_is_string(self):
        assert isinstance(__version__, str)

    def test_version_not_empty(self):
        assert len(__version__) > 0

    def test_version_falls_back_when_package_missing(self, monkeypatch):
        """When audnet is not installed (PackageNotFoundError), __init__ falls
        back to a sentinel version instead of raising at import time."""

        import importlib.metadata as importlib_metadata

        def _boom(_name):
            from importlib.metadata import PackageNotFoundError

            raise PackageNotFoundError("audnet")

        monkeypatch.setattr(importlib_metadata, "version", _boom)
        reloaded = importlib.reload(audnet)
        try:
            assert reloaded.__version__ == "0.0.0+unknown"
        finally:
            # Restore the real version so other tests are unaffected.
            monkeypatch.undo()
            importlib.reload(audnet)

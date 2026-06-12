"""Tests for the version module."""

from audnet import __version__


class TestVersion:
    def test_version_is_string(self):
        assert isinstance(__version__, str)

    def test_version_not_empty(self):
        assert len(__version__) > 0

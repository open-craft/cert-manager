"""
Tests for the module versions used by this package.

These are to ensure that pinned versions are used in development, testing, and
production.
"""

import certbot


def test_certbot_version():
    """
    Test that certbot module matches the pinned version.
    """
    assert certbot.__version__ == '1.1.0'

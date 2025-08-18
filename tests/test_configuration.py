"""
Test suite for configuration and validation components

Note: This module referenced IOConfiguration, which has been deprecated in favor of ConfigManager and
related settings utilities. The module is skipped until tests are updated to target the new config layer.
"""

import pytest

# Skip entire module; legacy tests removed
pytest.skip(
    "Deprecated configuration tests referencing IOConfiguration (removed).",
    allow_module_level=True,
)

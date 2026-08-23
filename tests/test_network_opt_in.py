import os

import pytest


@pytest.mark.network
@pytest.mark.integration
def test_live_active_discovery_requires_explicit_scope():
    scope = os.getenv("WIRESCOPE_LIVE_SCOPE")
    if not scope:
        pytest.skip(
            "Set WIRESCOPE_LIVE_SCOPE to an explicit authorized target to run "
            "live active discovery tests"
        )
    pytest.skip("Live Nmap execution is reserved for an explicit lab scope")

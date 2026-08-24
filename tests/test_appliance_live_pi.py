import os

import pytest

pytestmark = pytest.mark.live_pi


@pytest.mark.skipif(
    os.getenv("WIRESCOPE_LIVE_PI") != "1",
    reason="opt-in Raspberry Pi OS live install",
)
def test_raspberry_pi_os_lite_reaches_login():
    raise AssertionError(
        "Live Raspberry Pi install is deferred; set WIRESCOPE_LIVE_PI=1 on Pi hardware"
    )

import os

import pytest

pytestmark = pytest.mark.live_pi


@pytest.mark.skipif(
    os.getenv("WIRESCOPE_LIVE_PI") != "1",
    reason="opt-in Raspberry Pi hardware extra; unused for generic Linux",
)
def test_raspberry_pi_os_lite_reaches_login():
    raise AssertionError(
        "Live Raspberry Pi install is an unused later extra; "
        "set WIRESCOPE_LIVE_PI=1 only on Pi hardware"
    )

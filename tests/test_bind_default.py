from appliance.cli import build_parser
from config.settings import get_settings


def test_bind_defaults_are_loopback():
    parser = build_parser()
    args = parser.parse_args(["install", "--dry-run"])
    assert args.bind_host == "127.0.0.1"
    assert get_settings().bind_host == "127.0.0.1"

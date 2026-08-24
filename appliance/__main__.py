import sys

from appliance.cli import main


def _argv() -> list[str]:
    args = list(sys.argv[1:])
    if args and args[0] == "install" and "--bind-host" not in args:
        return ["install", "--bind-host", "0.0.0.0", *args[1:]]
    return args


if __name__ == "__main__":
    main(_argv())

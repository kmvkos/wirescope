import sys

from appliance.cli import build_parser


def _argv() -> list[str]:
    args = list(sys.argv[1:])
    if args and args[0] == "install" and "--bind-host" not in args:
        return ["install", "--bind-host", "0.0.0.0", *args[1:]]
    return args


def main(argv: list[str] | None = None) -> None:
    try:
        parser = build_parser()
        args = parser.parse_args(argv)
        raise SystemExit(args.handler(args))
    except KeyboardInterrupt:
        print("установка прервана / install interrupted", file=sys.stderr)
        raise SystemExit(130)


if __name__ == "__main__":
    main(_argv())

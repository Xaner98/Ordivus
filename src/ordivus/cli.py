"""Dünne CLI: parst Argumente, ruft ordivus.core, formatiert Ausgabe (Report stdout, Diagnose stderr)."""

import argparse
import sys
from collections import Counter
from enum import IntEnum
from importlib.metadata import version

from ordivus.core import config


class ExitCode(IntEnum):
    OK = 0
    INTERNAL = 1
    USAGE = 2  # von argparse selbst gesetzt
    DRIFT = 10
    POLICY = 11
    CONFIG = 12
    TARGET = 13
    PARTIAL = 14
    INVALID_PLAN = 15
    SIGINT = 130
    SIGTERM = 143


def _validate(args) -> ExitCode:
    try:
        docs = config.load(args.file)
    except config.ConfigError as e:
        for line in e.errors:
            print(line, file=sys.stderr)
        return ExitCode.CONFIG
    print(f"Configuration valid: {len(docs)} documents")
    for kind, count in sorted(Counter(d.kind for d in docs).items()):
        print(f"  {kind}: {count}")
    print(f"digest: {config.digest(docs)}")
    return ExitCode.OK


def _not_implemented(args) -> ExitCode:
    print(f"ordivus {args.command}: not implemented", file=sys.stderr)
    return ExitCode.INTERNAL


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ordivus")
    parser.add_argument("--version", action="version", version=f"ordivus {version('ordivus')}")
    commands = parser.add_subparsers(dest="command", required=True)

    cfg = commands.add_parser("config", help="configuration commands")
    cfg_commands = cfg.add_subparsers(dest="config_command", required=True)
    validate = cfg_commands.add_parser("validate", help="validate configuration")
    validate.add_argument("-f", "--file", required=True, help="config file or directory")
    validate.set_defaults(handler=_validate)

    for name in ("plan", "drift", "apply"):
        sub = commands.add_parser(name)
        sub.add_argument("-f", "--file", required=True, help="config file or directory")
        sub.add_argument("--format", choices=["human", "json"], default="human")
        sub.set_defaults(handler=_not_implemented)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return args.handler(args)
    except KeyboardInterrupt:
        return ExitCode.SIGINT

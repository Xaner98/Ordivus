"""Dünne CLI: parst Argumente, ruft ordivus.core, formatiert Ausgabe (Report stdout, Diagnose stderr)."""

import argparse
import json
import logging
import os
import signal
import stat
import sys
import traceback
from collections import Counter
from enum import IntEnum
from importlib.metadata import version

from ordivus.core import config, engine, export, policy, report


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
        engine.prepare(docs)
    except config.ConfigError as e:
        for line in e.errors:
            print(line, file=sys.stderr)
        return ExitCode.CONFIG
    print(f"Configuration valid: {len(docs)} documents")
    for kind, count in sorted(Counter(d.kind for d in docs).items()):
        print(f"  {kind}: {count}")
    print(f"digest: {config.digest(docs)}")
    return ExitCode.OK


class _JsonLog(logging.Formatter):
    def format(self, record):
        return json.dumps({"type": "log", "level": record.levelname.lower(), "message": record.getMessage()})


def _run(args) -> ExitCode:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_JsonLog() if args.format == "json" else logging.Formatter("%(levelname)s: %(message)s"))
    logger = logging.getLogger("ordivus")
    logger.addHandler(handler)
    try:
        docs = config.load(args.file)
        operator = policy.load(args.policy) if args.policy else policy.OperatorPolicy()
        result = engine.run(args.command, docs, operator, args.target)
    except config.ConfigError as e:
        for line in e.errors:
            logger.error("%s", line)
        return ExitCode.CONFIG
    except policy.PolicyError as e:
        logger.error("policy: %s", e)
        return ExitCode.POLICY
    finally:
        logger.removeHandler(handler)
    text = (report.render_json if args.format == "json" else report.render_human)(result) + "\n"
    code = ExitCode(report.exit_code(result, args.fail_on))
    if not args.output:
        sys.stdout.write(text)
    elif error := _write_private(args.output, text):
        # Exit-Code des Laufs bleibt (apply hat ggf. schon geändert); nur ein sonst grüner Lauf wird zu 1
        print(f"cannot write report to {args.output}: {error}", file=sys.stderr)
        return code or ExitCode.INTERNAL
    return code


def _export(args) -> ExitCode:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    logger = logging.getLogger("ordivus")
    logger.addHandler(handler)
    try:
        docs = config.load(args.file)
        operator = policy.load(args.policy) if args.policy else policy.OperatorPolicy()
        result = export.run(docs, operator, args.target, args.kind)
    except config.ConfigError as e:
        for line in e.errors:
            logger.error("%s", line)
        return ExitCode.CONFIG
    except policy.PolicyError as e:
        logger.error("policy: %s", e)
        return ExitCode.POLICY
    finally:
        logger.removeHandler(handler)
    text = export.dump(result.documents) if result.documents else ""
    print(f"exported {len(result.documents)} documents" + (" (incomplete, see warnings)" if result.incomplete else ""),
          file=sys.stderr)
    code = ExitCode.TARGET if result.incomplete else ExitCode.OK
    if not args.output:
        sys.stdout.write(text)
    elif error := _write_private(args.output, text):
        print(f"cannot write export to {args.output}: {error}", file=sys.stderr)
        return code or ExitCode.INTERNAL
    return code


def _write_private(path: str, text: str) -> str | None:
    """Report mit 0600 schreiben; kein Symlink, und eine vorhandene Datei nur, wenn sie eine reguläre Datei
    des aktuellen Nutzers ist (der Report kann Rechte- und Inventardetails enthalten). Fehlertext oder None."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid():
                return "not a regular file owned by the current user"
            os.fchmod(fd, 0o600)
            f.truncate(0)
            f.write(text)
    except OSError as e:
        return e.strerror or type(e).__name__
    return None


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
        sub.add_argument("--policy", help="operator security policy file (YAML or JSON)")
        sub.add_argument("--output", help="write the report to FILE instead of stdout")
        sub.add_argument("--target", action="append", help="only this target (repeatable)")
        if name == "drift":
            sub.add_argument("--fail-on", choices=["actionable", "unmanaged", "unknown", "any"])
        elif name == "plan":
            sub.add_argument("--fail-on", choices=["changes"])
        sub.set_defaults(handler=_run, fail_on=None)
    exp = commands.add_parser("export", help="write the live state of targets as configuration")
    exp.add_argument("-f", "--file", required=True, help="config file or directory with Targets and Credentials")
    exp.add_argument("--policy", help="operator security policy file (YAML or JSON)")
    exp.add_argument("-o", "--output", help="write the configuration to FILE instead of stdout")
    exp.add_argument("--target", action="append", help="only this target (repeatable)")
    exp.add_argument("--kind", action="append", help="only this resource kind (repeatable)")
    exp.set_defaults(handler=_export)
    return parser


class Terminated(BaseException):
    """SIGTERM; BaseException, damit kein ``except Exception`` der Engine den Abbruch schluckt."""


def _terminate(signum, frame):
    raise Terminated


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    previous = signal.signal(signal.SIGTERM, _terminate)  # Context-Manager (Locks, Sessions) räumen beim Abwickeln auf
    try:
        return args.handler(args)
    except KeyboardInterrupt:
        return ExitCode.SIGINT
    except Terminated:
        return ExitCode.SIGTERM
    except Exception as e:  # nur der Typ: Meldung und Traceback können Secrets enthalten
        print(f"internal error: {type(e).__name__} (set ORDIVUS_DEBUG=1 for details)", file=sys.stderr)
        if os.environ.get("ORDIVUS_DEBUG") == "1":
            traceback.print_exc()
        return ExitCode.INTERNAL
    finally:
        signal.signal(signal.SIGTERM, previous)

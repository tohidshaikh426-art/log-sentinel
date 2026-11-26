"""CLI entrypoint for `python -m log_sentinel`."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from log_sentinel.collector.agent import LogSentinelAgent, configure_logging
from log_sentinel.config.settings import ConfigError, load_collector_config


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="log_sentinel",
        description="Log Sentinel continuous Linux authentication log collector.",
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        default=None,
        help="Path to collector .env configuration file.",
    )
    parser.add_argument(
        "--from-beginning",
        action="store_true",
        help="Read existing log contents from byte 0 on first run instead of tailing EOF.",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single collection/flush cycle and exit.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and run local detection without sending data to Supabase.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        config = load_collector_config(
            args.env_file,
            dry_run=args.dry_run,
            start_at_end_override=False if args.from_beginning else None,
        )
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    configure_logging(config)
    agent = LogSentinelAgent(config)
    if args.once:
        summary = agent.run_once()
        print(summary)
        agent.client.close()
        agent.spool.close()
        return 0

    agent.run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

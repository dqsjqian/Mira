#!/usr/bin/env python3
"""Run CI consumer commands with their shared dependency environment leases."""
import argparse
import os
from pathlib import Path
import sys
from forgedeps.build_kit.session import run_session


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--environment', type=Path, action='append', default=[])
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command:
        parser.error('A command is required')
    receipts = list(args.environment)
    for flag in ('--build', '--test-dir', '--build-dir'):
        if flag in command:
            path = Path(command[command.index(flag) + 1]) / 'forgedeps-environment.json'
            if path.is_file():
                receipts.append(path)
    run_session([command], receipts=receipts,
                env=dict(os.environ, FORGEDEPS_PYTHON_EXECUTABLE=sys.executable))


if __name__ == '__main__':
    main()

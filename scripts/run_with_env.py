#!/usr/bin/env python3
"""Load a plain dotenv file without shell evaluation, then execute a command.

Existing process variables take precedence. No variable values are printed.
Supported: KEY=value, export KEY=value, quotes and trailing comments.
No substitution, command execution, or multiline values in the env file.
"""
import argparse
import os
import re
import shlex
from pathlib import Path


def parse_env(path):
    result = {}
    for number, raw in enumerate(Path(path).read_text(encoding='utf-8').splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('export '):
            line = line[7:].lstrip()
        key, separator, value = line.partition('=')
        if not separator or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', key.strip()):
            raise ValueError(f'invalid env assignment at line {number}')
        try:
            values = shlex.split(value, comments=True, posix=True)
        except ValueError:
            raise ValueError(f'invalid env quoting at line {number}') from None
        if len(values) > 1:
            raise ValueError(f'quote values containing spaces at line {number}')
        result[key.strip()] = values[0] if values else ''
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--env-file', default='.env')
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command:
        parser.error('a command is required after --')
    try:
        values = parse_env(args.env_file)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    env = dict(values, **os.environ)
    os.execvpe(command[0], command, env)


if __name__ == '__main__':
    main()

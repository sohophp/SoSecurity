#!/usr/bin/env python3
"""Keep the distributable security skill reference in sync with its source."""
import argparse
from pathlib import Path
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Check without writing')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    source = root / 'docs/php-website-security-checklist.md'
    target = root / 'skills/php-website-security-audit/references/php-website-security-checklist.md'
    content = source.read_bytes()
    if args.check:
        if not target.is_file() or target.read_bytes() != content:
            print('Skill reference differs from the maintained checklist.', file=sys.stderr)
            return 1
        print('Skill reference matches the maintained checklist.')
        return 0
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    print('Security audit skill reference synchronized.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

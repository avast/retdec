#!/usr/bin/env python3

"""A wrapper for fileinfo that:
- uses also external YARA patterns,
- is able to analyze archives (.a/.lib files).
"""

from __future__ import print_function

import argparse
import importlib
import os
import sys

utils = importlib.import_module('retdec-utils')
utils.check_python_version()
utils.ensure_script_is_being_run_from_installed_retdec()

try:
    retdec_archive_decompiler = importlib.import_module('retdec-archive-decompiler')
    ArchiveDecompiler = retdec_archive_decompiler.ArchiveDecompiler
except ImportError:
    ArchiveDecompiler = None

sys.stdout = utils.Unbuffered(sys.stdout)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
FILEINFO = os.path.join(SCRIPT_DIR, 'retdec-fileinfo')
INSTALL_SHARE_YARA_DIR = os.path.join(SCRIPT_DIR, '..', 'share', 'retdec', 'support', 'generic', 'yara_patterns')

FILEINFO_EXTERNAL_YARA_PRIMARY_CRYPTO_DATABASES = [
    os.path.join(INSTALL_SHARE_YARA_DIR, 'signsrch', 'signsrch.yara'),
    os.path.join(INSTALL_SHARE_YARA_DIR, 'signsrch', 'signsrch.yarac')]
FILEINFO_EXTERNAL_YARA_EXTRA_CRYPTO_DATABASES = [
    os.path.join(INSTALL_SHARE_YARA_DIR, 'signsrch', 'signsrch_regex.yara'),
    os.path.join(INSTALL_SHARE_YARA_DIR, 'signsrch', 'signsrch_regex.yarac')]

def parse_args():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('-j', '--json',
                        dest='json',
                        action='store_true',
                        help='Set to forward --json to the archive decompilation script.')

    parser.add_argument('--use-external-patterns',
                        dest='external_patterns',
                        action='store_true',
                        help='Should use external patterns')

    return parser.parse_known_args()


def get_input_file(unknownargs):
    """Find the positional input using fileinfo.cpp doParams option arities."""
    value_options = {'-m', '--malware', '-C', '--crypto', '-o', '--other',
                     '-c', '--config', '--fileinfo-config', '--max-memory',
                     '--ep-bytes', '--dlls'}
    tokens = []
    for arg in unknownargs:
        name, equals, value = arg.partition('=')
        if equals and (name in value_options or name == '--no-hashes'):
            tokens.extend([name, value])
        else:
            tokens.append(arg)
    i = 0
    while i < len(tokens):
        arg = tokens[i]
        if arg in value_options:
            i += 2
        elif arg == '--no-hashes':
            i += 2 if i + 1 < len(tokens) and tokens[i + 1] in {'file', 'verbose', 'all'} else 1
        elif not arg.startswith('-'):
            return arg
        else:
            i += 1
    return None


def main():
    args, unknownargs = parse_args()

    input = get_input_file(unknownargs)

    # When analyzing an archive, use the archive decompilation script `--list`
    # instead of `fileinfo` because fileinfo is currently unable to analyze
    # archives.
    if input and utils.has_archive_signature(input):
        archive_decompiler_args = [input, '--list']

        if args.json:
            archive_decompiler_args.append('--json')

        assert ArchiveDecompiler is not None, "You need to install RetDec with Decompiler in order to analyze archives"
        decompiler = ArchiveDecompiler(archive_decompiler_args)
        sys.exit(decompiler.decompile_archive())

    # We are not analyzing an archive, so proceed to fileinfo.
    fileinfo_params = unknownargs

    if args.json:
        fileinfo_params.append('--json')

    for par in FILEINFO_EXTERNAL_YARA_PRIMARY_CRYPTO_DATABASES:
        fileinfo_params.extend(['--crypto', par])

    if args.external_patterns:
        for par in FILEINFO_EXTERNAL_YARA_EXTRA_CRYPTO_DATABASES:
            fileinfo_params.extend(['--crypto', par])

    _, ret, _ = utils.CmdRunner.run_cmd([FILEINFO] + fileinfo_params)
    sys.exit(ret)


if __name__ == "__main__":
    main()

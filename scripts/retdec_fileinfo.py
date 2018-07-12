#!/usr/bin/env python3

"""A wrapper for fileinfo that:
- uses also external YARA patterns,
- is able to analyze archives (.a/.lib files).
"""

import argparse
import subprocess
import sys

import retdec_config as config
from retdec_utils import Utils
from retdec_archive_decompiler import ArchiveDecompiler

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
    """Find path to the input file.
    We take the first parameter that does not start with a dash. This is a
    simplification and may not work in all cases. A proper solution would
    need to parse fileinfo parameters, which would be complex.
    """
    for arg in unknownargs:
        if not arg.startswith('-'):
            return arg
    return None

if __name__ == '__main__':
    args, unknownargs = parse_args()

    input = get_input_file(unknownargs)

    # When analyzing an archive, use the archive decompilation script `--list`
    # instead of `fileinfo` because fileinfo is currently unable to analyze
    # archives.
    if input and Utils.has_archive_signature(input):
        archive_decompiler_args = [input, '--list']

        if args.json:
            archive_decompiler_args.append('--json')

        decompiler = ArchiveDecompiler(archive_decompiler_args)
        sys.exit(decompiler.decompile_archive())

    # We are not analyzing an archive, so proceed to fileinfo.
    fileinfo_params = unknownargs

    if args.json:
        fileinfo_params.append('--json')

    for par in config.FILEINFO_EXTERNAL_YARA_PRIMARY_CRYPTO_DATABASES:
        fileinfo_params.extend(['--crypto', par])

    if args.external_patterns:
        for par in config.FILEINFO_EXTERNAL_YARA_EXTRA_CRYPTO_DATABASES:
            fileinfo_params.extend(['--crypto', par])

    subprocess.call([config.FILEINFO, *fileinfo_params])

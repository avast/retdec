#! /usr/bin/env python3

"""When analyzing an archive, use the archive decompilation script `--list` instead of
`fileinfo` because fileinfo is currently unable to analyze archives.

First, we have to find path to the input file. We take the first parameter
that does not start with a dash. This is a simplification and may not work in
all cases. A proper solution would need to parse fileinfo parameters, which
would be complex.
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

    parser.add_argument('file',
                        metavar='FILE',
                        help='File to analyze.')

    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()

    if Utils.has_archive_signature(args.file):
        # The input file is not an archive.

        # The input file is an archive, so use the archive decompilation script
        # instead of fileinfo.
        archive_decompiler_args = [args.file, '--list']

        if args.json:
            archive_decompiler_args.append('--json')

        res = ArchiveDecompiler(archive_decompiler_args).decompile_archive()
        sys.exit(res)

    # We are not analyzing an archive, so proceed to fileinfo.
    fileinfo_params = [args.file]

    for par in config.FILEINFO_EXTERNAL_YARA_PRIMARY_CRYPTO_DATABASES:
        fileinfo_params.extend(['--crypto', par])

    if args.external_patterns:
        for par in config.FILEINFO_EXTERNAL_YARA_EXTRA_CRYPTO_DATABASES:
            fileinfo_params.extend(['--crypto', par])

    subprocess.call([config.FILEINFO] + fileinfo_params, shell=True)

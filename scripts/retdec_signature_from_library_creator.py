#! /usr/bin/env python3

"""Create Yara rules file from static libraries."""

import argparse
import shutil
import sys
import os
import subprocess
import tempfile
from pathlib import Path

import retdec_config as config
from retdec_utils import Utils


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument('input',
                        nargs='+',
                        metavar='FILE',
                        help='Input file(s)')

    parser.add_argument('-n', '--no-cleanup',
                        dest='no_cleanup',
                        action='store_true',
                        help='Temporary .pat files will be kept.')

    parser.add_argument('-o', '--output',
                        dest='output',
                        metavar='FILE',
                        required=True,
                        help='Where result(s) will be stored.')

    parser.add_argument('-m', '--min-pure',
                        dest='min_pure',
                        default=16,
                        help='Minimum pure information needed for patterns.')

    parser.add_argument('-i', '--ignore-nops',
                        dest='ignore_nops',
                        help='Ignore trailing NOPs when computing (pure) size.')

    parser.add_argument('-l', '--logfile',
                        dest='logfile',
                        action='store_true',
                        help='Add log-file with \'.log\' suffix from pat2yara.')

    parser.add_argument('-b', '--bin2pat-only',
                        dest='bin_to_pat_only',
                        action='store_true',
                        help='Stop after bin2pat.')

    return parser.parse_args()


class SigFromLib:
    def __init__(self, _args):
        self.args = _args
        self.ignore_nop = ''
        self.file_path = ''
        self.tmp_dir_path = ''

    def print_error_and_cleanup(self, message):
        """Print error message and clean up temporary files.
        """

        # Cleanup.
        if not self.args.no_cleanup:
            if os.path.exists(self.tmp_dir_path):
                Utils.remove_forced(self.tmp_dir_path)

        Utils.print_error_and_die(message + '.')

    def _check_arguments(self):

        for f in self.args.input:
            if not os.path.isfile(f):
                self.print_error_and_cleanup('input %s is not a valid file nor argument' % f)
                return False

        self.file_path = self.args.output
        dir_name = os.path.dirname(Utils.get_realpath(self.file_path))
        self.tmp_dir_path = os.path.join(dir_name, 'XXXXXXXXX')

        if self.args.ignore_nops:
            self.ignore_nop = '--ignore-nops'

        return True

    def run(self):
        if not self._check_arguments():
            return 1

        pattern_files = []
        object_dirs = []

        # Create .pat files for every library.
        for lib_path in self.args.input:
            # Check for invalid archives.
            if not Utils.is_valid_archive(lib_path):
                print('ignoring file %s - not valid archive' % lib_path)
                continue

            # Get library name for .pat file.
            lib_name = Path(lib_path).resolve().stem

            # Create sub-directory for object files.
            object_dir = os.path.join(self.tmp_dir_path, lib_name) + '-objects'
            object_dirs = [object_dir]
            os.makedirs(object_dir)

            # Extract all files to temporary folder.
            subprocess.call([config.AR, lib_path, '--extract', '--output', object_dir], shell=True)

            # List all extracted objects.
            objects = []

            for root, dirs, files in os.walk(object_dir):
                for f in files:
                    fname = os.path.join(root, f)
                    if os.path.isfile(fname):
                        objects.append(fname)

            # Extract patterns from library.
            pattern_file = os.path.join(self.tmp_dir_path, lib_name) + '.pat'
            pattern_files = [pattern_file]
            result = subprocess.call([config.BIN2PAT, '-o', pattern_file] + objects, shell=True)

            if result != 0:
                self.print_error_and_cleanup('utility bin2pat failed when processing %s' % lib_path)

            # Remove extracted objects continuously.
            if not self.args.no_cleanup:
                if os.path.exists(object_dir):
                    shutil.rmtree(object_dir)

        # Skip second step - only .pat files will be created.
        if self.args.bin_to_pat_only:
            if not self.args.no_cleanup:
                for d in object_dirs:
                    if os.path.exists(d):
                        shutil.rmtree(d)
            # sys.exit(0)
            return 1

        # Create final .yara file from .pat files.
        if self.args.logfile:
            result = subprocess.call(
                [config.PAT2YARA] + pattern_files + ['--min-pure', str(self.args.min_pure), '-o', self.file_path, '-l',
                                                     self.file_path + '.log', self.ignore_nop,
                                                     str(self.args.ignore_nops)],
                shell=True)

            if result != 0:
                self.print_error_and_cleanup('utility pat2yara failed')
        else:
            result = subprocess.call(
                [config.PAT2YARA] + pattern_files + ['--min-pure', str(self.args.min_pure), '-o', self.file_path,
                                                     self.ignore_nop, str(self.args.ignore_nops)], shell=True)

            if result != 0:
                self.print_error_and_cleanup('utility pat2yara failed')

        # Do cleanup.
        if not self.args.no_cleanup:
            Utils.remove_forced(self.tmp_dir_path)

        return result


if __name__ == '__main__':
    args = parse_args()

    sig = SigFromLib(args)

    sys.exit(sig.run())

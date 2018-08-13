#! /usr/bin/env python3

"""Create Yara rules file from static libraries."""

import argparse
import shutil
import sys
import os
import subprocess
import tempfile

import importlib
config = importlib.import_module('retdec-config')
utils = importlib.import_module('retdec-utils')

CmdRunner = utils.CmdRunner
sys.stdout = utils.Unbuffered(sys.stdout)


def parse_args(args):
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

    return parser.parse_args(args)


class SigFromLib:
    def __init__(self, _args):
        self.args = parse_args(_args)
        self.ignore_nop = ''
        self.tmp_dir_path = ''

    def print_error_and_cleanup(self, message):
        if not self.args.no_cleanup:
            shutil.rmtree(self.tmp_dir_path, ignore_errors=True)
        utils.print_error(message)

    def _check_arguments(self):
        for f in self.args.input:
            if not os.path.isfile(f):
                self.print_error_and_cleanup('input %s is not a valid file' % f)
                return False

        dir_name = os.path.dirname(os.path.abspath(self.args.output))
        self.tmp_dir_path = tempfile.mkdtemp(dir=dir_name)

        if self.args.ignore_nops:
            self.ignore_nop = '--ignore-nops'

        return True

    def run(self):
        if not self._check_arguments():
            return 1

        cmd = CmdRunner()
        pattern_files = []
        object_dirs = []

        # Create .pat files for every library.
        for lib_path in self.args.input:
            # Check for invalid archives.
            if not utils.is_valid_archive(lib_path):
                print('ignoring file %s - not valid archive' % lib_path)
                continue

            # Get library name for .pat file.
            lib_name = os.path.splitext(os.path.basename(lib_path))[0]

            # Create sub-directory for object files.
            object_dir = os.path.join(self.tmp_dir_path, lib_name) + '-objects'
            object_dirs = [object_dir]
            os.makedirs(object_dir, exist_ok=True)

            # Extract all files to temporary folder.
            cmd.run_cmd([config.AR, lib_path, '--extract', '--output', object_dir], discard_stdout=True, discard_stderr=True)

            # List all extracted objects.
            objects = []

            for root, dirs, files in os.walk(object_dir):
                for f in files:
                    fname = os.path.join(root, f)
                    if os.path.isfile(fname):
                        objects.append(fname)

            # Extract patterns from library.
            pattern_file = os.path.join(self.tmp_dir_path, lib_name) + '.pat'
            pattern_files.append(pattern_file)
            _, result, _ = cmd.run_cmd([config.BIN2PAT, '-o', pattern_file] + objects, discard_stdout=True, discard_stderr=True)

            if result != 0:
                self.print_error_and_cleanup('utility bin2pat failed when processing %s' % lib_path)
                return 1

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
            return 0

        # Create final .yara file from .pat files.
        pat2yara_args = [config.PAT2YARA] + pattern_files + ['--min-pure', str(self.args.min_pure), '-o', self.args.output]
        if self.args.logfile:
            pat2yara_args.extend(['-l', self.args.output + '.log'])
        if self.ignore_nop:
            pat2yara_args.extend([self.ignore_nop, str(self.args.ignore_nops)])

        _, result, _ = cmd.run_cmd(pat2yara_args, discard_stdout=True, discard_stderr=True)

        if result != 0:
            self.print_error_and_cleanup('utility pat2yara failed')
            return 1

        # Do cleanup.
        if not self.args.no_cleanup:
            shutil.rmtree(self.tmp_dir_path, ignore_errors=True)

        return result


if __name__ == '__main__':
    sig = SigFromLib(sys.argv[1:])
    sys.exit(sig.run())

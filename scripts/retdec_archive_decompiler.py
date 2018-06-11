#! /usr/bin/env python3

import argparse
import os
import re
import subprocess
import sys

import retdec_config as config
from retdec_utils import Utils
from retdec_utils import CmdRunner


def parse_args():
    parser = argparse.ArgumentParser(description='Runs the decompilation script with the given optional arguments over'
                                                 ' all files in the given static library or prints list of files in'
                                                 ' plain text with --plain argument or in JSON format with'
                                                 ' --json argument. You can pass arguments for decompilation after'
                                                 ' double-dash -- argument.',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument("--plain",
                        dest="plain_format",
                        help="print list of files in plain text")

    parser.add_argument("--json",
                        dest="json_format",
                        help="print list of files in json format")

    parser.add_argument("--list",
                        dest="list_mode",
                        help="list")

    parser.add_argument("--",
                        nargs='+',
                        dest="arg_list",
                        help="args passed to the decompiler")

    parser.add_argument("file",
                        help="path")

    return parser.parse_args()


class ArchiveDecompiler:
    def __init__(self, _args):
        self.args = _args

        self.decompiler_sh_args = ''
        self.timeout = 300
        self.tmp_archive = ''
        self.use_json_format = False
        self.use_plain_format = False
        self.enable_list_mode = False
        self.library_path = ''
        self.file_count = 0

    def _print_error_plain_or_json(self, error):
        """Prints error in either plain text or JSON format.
        One argument required: error message.
        """
        if self.use_json_format:
            message = re.escape(error)
            print('{')
            print('    \'error\' : \'' + message + '\'')
            print('}')
            # exit(1)
        else:
            # Otherwise print in plain text.
            Utils.print_error_and_die(error)

    def _cleanup(self):
        """Cleans up all temporary files.
        No arguments accepted.
        """
        if os.path.exists(self.tmp_archive):
            Utils.remove_forced(self.tmp_archive)

    def _check_arguments(self):

        if self.args.list_mode:
            self.enable_list_mode = True

        if self.args.plain_format:
            if self.use_json_format:
                Utils.print_error_and_die('Arguments --plain and --json are mutually exclusive.')
                return False
            else:
                self.enable_list_mode = True
                self.use_plain_format = True

        if self.args.json_format:
            if self.args.args.plain_format:
                Utils.print_error_and_die('Arguments --plain and --json are mutually exclusive.')
                return False
            else:
                self.enable_list_mode = True
                self.use_json_format = True

        if self.args.arg_list:
            self.decompiler_sh_args = ' '.join(self.args.arg_list)

        if self.args.file:
            if not (os.path.isfile(self.args.file)):
                Utils.print_error_and_die('Input %s is not a valid file.' % self.args.file)
                return False

            self.library_path = self.args.file

        if self.library_path == '':
            self._print_error_plain_or_json('No input file.')
            return False

        return True

    def decompile_archive(self):

        # Check arguments
        if not self._check_arguments():
            return

        # Check for archives packed in Mach-O Universal Binaries.
        if Utils.is_macho_archive(self.library_path):
            if self.enable_list_mode:
                if self.use_json_format:
                    subprocess.call([config.EXTRACT, '--objects', '--json', self.library_path], shell=True)
                else:
                    subprocess.call([config.EXTRACT, '--objects', self.library_path], shell=True)
                # sys.exit(1)

            self.tmp_archive = self.library_path + '.a'
            subprocess.call([config.EXTRACT, '--best', '--out', self.tmp_archive, self.library_path], shell=True)
            self.library_path = self.tmp_archive

        # Check for thin archives.
        if Utils.has_thin_archive_signature(self.library_path) == 0:
            self._print_error_plain_or_json('File is a thin archive and cannot be decompiled.')
            return

        # Check if file is archive
        if not Utils.is_valid_archive(self.library_path):
            self._print_error_plain_or_json('File is not supported archive or is not readable.')
            return

        # Check number of files.
        self.file_count = Utils.archive_object_count(self.library_path)

        if self.file_count <= 0:
            self._print_error_plain_or_json('No files found in archive.')
            return

        # List only mode.
        if self.enable_list_mode:
            if self.use_json_format:
                Utils.archive_list_numbered_content_json(self.library_path)
            else:
                Utils.archive_list_numbered_content(self.library_path)

            self._cleanup()
            # sys.exit(0)

        # Run the decompilation script over all the found files.
        print('Running \`%s' % config.DECOMPILER_SH, end='')

        if self.decompiler_sh_args != '':
            print(self.decompiler_sh_args, end='')

        print('\` over %d files with timeout %d s. (run \`kill %d \` to terminate this script)...' % (
            self.file_count, self.timeout, os.getpid()), file=sys.stderr)

        cmd = CmdRunner()
        for i in range(self.file_count):
            file_index = (i + 1)
            print('%d/%d\t\t' % (file_index, self.file_count))

            # We have to use indexes instead of names because archives can contain multiple files with same name.
            log_file = self.library_path + '.file_' + str(file_index) + '.log.verbose'

            # Do not escape!
            output, _, timeouted = cmd.run_cmd([config.DECOMPILER_SH, '--ar-index=' + str(i), '-o',
                                                self.library_path + '.file_' + str(file_index) + '.c',
                                                self.library_path, self.decompiler_sh_args], timeout=self.timeout)

            with open(log_file, 'wb') as f:
                f.write(output)

            if timeouted:
                print('[TIMEOUT]')
            else:
                print('[OK]')

        self._cleanup()
        # sys.exit(0)


if __name__ == '__main__':
    args = parse_args()

    archive_decompiler = ArchiveDecompiler(args)
    archive_decompiler.decompile_archive()

    sys.exit(0)

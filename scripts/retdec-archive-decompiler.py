#!/usr/bin/env python3

from __future__ import print_function

import argparse
import importlib
import os
import re
import shutil
import sys

utils = importlib.import_module('retdec-utils')
utils.check_python_version()
CmdRunner = utils.CmdRunner


sys.stdout = utils.Unbuffered(sys.stdout)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DECOMPILER = os.path.join(SCRIPT_DIR, 'retdec-decompiler')
EXTRACT = os.path.join(SCRIPT_DIR, 'retdec-macho-extractor')

def parse_args(args):
    parser = argparse.ArgumentParser(description='Runs the decompilation with the given optional arguments over'
                                                 ' all files in the given static library or prints list of files in'
                                                 ' plain text with --plain argument or in JSON format with'
                                                 ' --json argument. You can pass arguments for decompilation after'
                                                 ' double-dash -- argument.',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument("file",
                        metavar='FILE',
                        help='File to analyze.')

    parser.add_argument("--plain",
                        dest="plain_format",
                        action='store_true',
                        help="print list of files in plain text")

    parser.add_argument("--json",
                        dest="json_format",
                        action='store_true',
                        help="print list of files in json format")

    parser.add_argument("--list",
                        dest="list_mode",
                        action='store_true',
                        help="list")

    parser.add_argument("--",
                        nargs='+',
                        dest="arg_list",
                        help="args passed to the decompiler")

    return parser.parse_args(args)


class ArchiveDecompiler:
    def __init__(self, _args):
        self.args = parse_args(_args)

        self.decompiler_args = ''
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
        else:
            # Otherwise print in plain text.
            utils.print_error(error)

    def _cleanup(self):
        """Cleans up all temporary files.
        No arguments accepted.
        """
        shutil.rmtree(self.tmp_archive, ignore_errors=True)

    def _check_arguments(self):
        if self.args.list_mode:
            self.enable_list_mode = True

        if self.args.plain_format:
            if self.use_json_format:
                utils.print_error('Arguments --plain and --json are mutually exclusive.')
                return False
            else:
                self.enable_list_mode = True
                self.use_plain_format = True

        if self.args.json_format:
            if self.args.plain_format:
                utils.print_error('Arguments --plain and --json are mutually exclusive.')
                return False
            else:
                self.enable_list_mode = True
                self.use_json_format = True

        if self.args.arg_list:
            self.decompiler_args = self.args.arg_list

        if self.args.file:
            if not os.path.isfile(self.args.file):
                utils.print_error('Input %s is not a valid file.' % self.args.file)
                return False

            self.library_path = self.args.file

        if self.library_path == '':
            self._print_error_plain_or_json('No input file.')
            return False

        return True

    def decompile_archive(self):
        # Check arguments
        if not self._check_arguments():
            return 1

        # Check for archives packed in Mach-O Universal Binaries.
        if utils.is_macho_archive(self.library_path):
            if self.enable_list_mode:
                if self.use_json_format:
                    CmdRunner.run_cmd([EXTRACT, '--objects', '--json', self.library_path])
                else:
                    CmdRunner.run_cmd([EXTRACT, '--objects', self.library_path])
                return 1

            self.tmp_archive = self.library_path + '.a'
            CmdRunner.run_cmd([EXTRACT, '--best', '--out', self.tmp_archive, self.library_path])
            self.library_path = self.tmp_archive

        # Check for thin archives.
        if utils.has_thin_archive_signature(self.library_path):
            self._print_error_plain_or_json('File is a thin archive and cannot be decompiled.')
            return 1

        # Check if file is archive
        if not utils.is_valid_archive(self.library_path):
            self._print_error_plain_or_json('File is not supported archive or is not readable.')
            return 1

        # Check number of files.
        self.file_count = utils.archive_object_count(self.library_path)

        if self.file_count <= 0:
            self._print_error_plain_or_json('No files found in archive.')
            return 1

        # List only mode.
        if self.enable_list_mode:
            if self.use_json_format:
                utils.archive_list_numbered_content_json(self.library_path)
            else:
                utils.archive_list_numbered_content(self.library_path)

            self._cleanup()
            return 0

        # Run the decompilation over all the found files.
        print('Running `%s' % DECOMPILER, end='')

        if self.decompiler_args:
            print(' '.join(self.decompiler_args), end='')

        print('` over %d files with timeout %d s. (run `kill %d ` to terminate this script)...' % (
            self.file_count, self.timeout, os.getpid()), file=sys.stderr)

        for i in range(self.file_count):
            file_index = (i + 1)
            print('%d/%d\t\t' % (file_index, self.file_count))

            # We have to use indexes instead of names because archives can contain multiple files with same name.
            log_file = self.library_path + '.file_' + str(file_index) + '.log.verbose'

            # Do not escape!
            arg_list = [
                sys.executable,
                DECOMPILER,
                '--ar-index=' + str(i),
                '-o', self.library_path + '.file_' + str(file_index) + '.c',
                self.library_path,
            ]
            if self.decompiler_args:
                arg_list.append(self.decompiler_args)
            output, rc, timeouted = CmdRunner.run_cmd(
                arg_list,
                timeout=self.timeout,
                buffer_output=True,
            )

            with open(log_file, 'w') as f:
                f.write(output)

            if timeouted:
                print('[TIMEOUT]')
            elif rc != 0:
                print('[FAIL]')
            else:
                print('[OK]')

        self._cleanup()
        return 0


if __name__ == '__main__':
    archive_decompiler = ArchiveDecompiler(sys.argv[1:])
    sys.exit(archive_decompiler.decompile_archive())

#!/usr/bin/env python3

"""
The script tries to unpack the given executable file by using any
of the supported unpackers, which are at present:
   * generic unpacker
   * upx

Required argument:
   * (packed) binary file

Optional arguments:
   * desired name of unpacked file
   * use extended exit codes

Returns:
   * 0 successfully unpacked
"""

import argparse
import os
import shutil
import sys

import importlib
config = importlib.import_module('retdec-config')
utils = importlib.import_module('retdec-utils')

CmdRunner = utils.CmdRunner
sys.stdout = utils.Unbuffered(sys.stdout)


def parse_args(_args):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument('file',
                        metavar='FILE',
                        help='The input file.')

    parser.add_argument('-e', '--extended-exit-codes',
                        dest='extended_exit_codes',
                        action='store_true',
                        help='Use more granular exit codes than just 0/1.')

    parser.add_argument('-o', '--output',
                        dest='output',
                        metavar='FILE',
                        help='Output file (default: file-unpacked).')

    parser.add_argument('--max-memory',
                        dest='max_memory',
                        help='Limit the maximal memory of retdec-unpacker to N bytes.')

    parser.add_argument('--max-memory-half-ram',
                        dest='max_memory_half_ram',
                        action='store_true',
                        help='Limit the maximal memory of retdec-unpacker to half of system RAM.')

    return parser.parse_args(_args)


class Unpacker:
    RET_UNPACK_OK = 0
    #  1 generic unpacker - nothing to do; upx succeeded (--extended-exit-codes only)
    RET_UNPACKER_NOTHING_TO_DO_OTHERS_OK = 1
    #  2 not packed or unknown packer
    RET_NOTHING_TO_DO = 2
    #  3 generic unpacker failed; upx succeeded (--extended-exit-codes only)
    RET_UNPACKER_FAILED_OTHERS_OK = 3
    #  4 generic unpacker failed; upx not succeeded
    RET_UNPACKER_FAILED = 4

    UNPACKER_EXIT_CODE_OK = 0
    # 1 There was not found matching plugin.
    UNPACKER_EXIT_CODE_NOTHING_TO_DO = 1
    # 2 At least one plugin failed at the unpacking of the file.
    UNPACKER_EXIT_CODE_UNPACKING_FAILED = 2
    # 3 Error with preprocessing of input file before unpacking.
    UNPACKER_EXIT_CODE_PREPROCESSING_ERROR = 3
    #
    UNPACKER_EXIT_CODE_OTHER = -1

    def __init__(self, _args):
        self.args = parse_args(_args)
        self.input = ''
        self.output = ''
        self.log_output = False
        self.unpacker_output = ''

    def _check_arguments(self):
        """Check proper combination of input arguments.
        """

        # Check whether the input file was specified.
        if self.args.file is None:
            utils.print_error('No input file was specified')
            return False

        if not os.access(self.args.file, os.R_OK):
            utils.print_error('The input file %s does not exist or is not readable' % self.args.file)
            return False

        # Conditional initialization.
        if not self.args.output:
            self.output = self.args.file + '-unpacked'
        else:
            self.output = self.args.output

        if self.args.max_memory is not None:
            try:
                int(self.args.max_memory)
            except ValueError:
                utils.print_error('Invalid value for --max-memory: %s (expected a positive integer)'
                                  % self.args.max_memory)
                return False

        # Convert to absolute paths.
        self.input = os.path.abspath(self.args.file)
        self.output = os.path.abspath(self.output)

        return True

    def _unpack(self, output):
        """Try to unpack the given file.
        """

        unpacker_params = [self.input, '-o', output]

        if self.args.max_memory:
            unpacker_params.extend(['--max-memory', self.args.max_memory])
        elif self.args.max_memory_half_ram:
            unpacker_params.append('--max-memory-half-ram')

        cmd = CmdRunner()

        self._print('\n##### Trying to unpack ' + self.input + ' into ' + output + ' by using generic unpacker...')
        out, unpacker_rc, _ = cmd.run_cmd([config.UNPACKER] + unpacker_params, buffer_output=True, print_run_msg=True)
        self._print(out)

        if unpacker_rc == self.UNPACKER_EXIT_CODE_OK:
            self._print('##### Unpacking by using generic unpacker: successfully unpacked')
            return self.unpacker_output, self.RET_UNPACK_OK
        elif unpacker_rc == self.UNPACKER_EXIT_CODE_NOTHING_TO_DO:
            self._print('##### Unpacking by using generic unpacker: nothing to do')
        else:
            # Do not return -> try the next unpacker
            self._print('##### Unpacking by using generic unpacker: failed')

        if utils.tool_exists('upx'):
            # Do not return -> try the next unpacker
            # Try to unpack via UPX
            self._print('\n##### Trying to unpack ' + self.input + ' into ' + output + ' by using UPX...')
            out, upx_rc, _ = cmd.run_cmd(['upx', '-d', self.input, '-o', output], buffer_output=True, discard_stdout=True, print_run_msg=True)
            self._print(out)

            if upx_rc == 0:
                self._print('##### Unpacking by using UPX: successfully unpacked')
                if self.args.extended_exit_codes:
                    if unpacker_rc == self.UNPACKER_EXIT_CODE_NOTHING_TO_DO:
                        return self.unpacker_output, self.RET_UNPACKER_NOTHING_TO_DO_OTHERS_OK
                    elif unpacker_rc >= self.UNPACKER_EXIT_CODE_UNPACKING_FAILED:
                        return self.unpacker_output, self.RET_UNPACKER_FAILED_OTHERS_OK
                else:
                    return self.unpacker_output, self.RET_UNPACK_OK
            else:
                # We cannot distinguish whether upx failed or the input file was
                # not upx-packed
                self._print('##### Unpacking by using UPX: nothing to do')
        else:
            self._print('##### \'upx\' not available: nothing to do')

        if unpacker_rc >= self.UNPACKER_EXIT_CODE_UNPACKING_FAILED:
            return self.unpacker_output, self.RET_UNPACKER_FAILED
        else:
            return self.unpacker_output, self.RET_NOTHING_TO_DO

    def unpack_all(self, log_output=False):
        self.log_output = log_output
        if not self._check_arguments():
            return '', self.UNPACKER_EXIT_CODE_OTHER

        res_rc = self.UNPACKER_EXIT_CODE_OTHER
        res_out = ''
        tmp_output = self.output + '.tmp'

        while True:
            unpacker_out, return_code = self._unpack(tmp_output)

            res_out += unpacker_out + '\n'

            if return_code == self.RET_UNPACK_OK or return_code == self.RET_UNPACKER_NOTHING_TO_DO_OTHERS_OK \
                    or return_code == self.RET_UNPACKER_FAILED_OTHERS_OK:
                res_rc = return_code

                shutil.move(tmp_output, self.output)
                self.input = self.output
            else:
                # Remove the temporary file, just in case some of the unpackers crashed
                # during unpacking and left it on the disk (e.g. upx).
                utils.remove_file_forced(tmp_output)
                break

        return (res_out, return_code) if res_rc == self.UNPACKER_EXIT_CODE_OTHER else (res_out, res_rc)

    def _print(self, line=''):
        if self.log_output:
            self.unpacker_output = self.unpacker_output + line
        else:
            print(line)


if __name__ == '__main__':
    unpacker = Unpacker(sys.argv[1:])
    _, rc = unpacker.unpack_all()
    sys.exit(rc)

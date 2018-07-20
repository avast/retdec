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
retdec_utils = importlib.import_module('retdec-utils')

Utils = retdec_utils.Utils
CmdRunner = retdec_utils.CmdRunner


sys.stdout = retdec_utils.Unbuffered(sys.stdout)


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

    def _check_arguments(self):
        """Check proper combination of input arguments.
        """

        # Check whether the input file was specified.
        if self.args.file is None:
            Utils.print_error('No input file was specified')
            return False

        if not os.access(self.args.file, os.R_OK):
            Utils.print_error('The input file %s does not exist or is not readable' % self.args.file)
            return False

        # Conditional initialization.
        if not self.args.output:
            self.output = self.args.file + '-unpacked'
        else:
            self.output = self.args.output

        if self.args.max_memory is not None:
            try:
                max_memory = int(self.args.max_memory)
                if max_memory > 0:
                    return True
            except ValueError:
                Utils.print_error('Invalid value for --max-memory: %s (expected a positive integer)'
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

        print()
        print('##### Trying to unpack ' + self.input + ' into ' + output + ' by using generic unpacker...')
        print('RUN: ' + config.UNPACKER + ' '.join(unpacker_params))

        cmd = CmdRunner()
        unpacker_output, unpacker_rc, _ = cmd.run_cmd([config.UNPACKER] + unpacker_params, buffer_output=True)
        print(unpacker_output)

        if unpacker_rc == self.UNPACKER_EXIT_CODE_OK:
            print('##### Unpacking by using generic unpacker: successfully unpacked')
            return unpacker_output, self.RET_UNPACK_OK
        elif unpacker_rc == self.UNPACKER_EXIT_CODE_NOTHING_TO_DO:
            print('##### Unpacking by using generic unpacker: nothing to do')
        else:
            # Do not return -> try the next unpacker
            # UNPACKER_EXIT_CODE_UNPACKING_FAILED
            # UNPACKER_EXIT_CODE_PREPROCESSING_ERROR
            print('##### Unpacking by using generic unpacker: failed')

        if Utils.tool_exists('upx'):
            # Do not return -> try the next unpacker
            # Try to unpack via UPX
            print()
            print('##### Trying to unpack ' + self.input + ' into ' + output + ' by using UPX...')
            print('RUN: upx -d ' + self.input + ' -o ' + output)

            unpacker_output, upx_rc, _ = cmd.run_cmd(['upx', '-d', self.input, '-o', output], buffer_output=True)

            if upx_rc == 0:
                print('##### Unpacking by using UPX: successfully unpacked')
                if self.args.extended_exit_codes:
                    if unpacker_rc == self.UNPACKER_EXIT_CODE_NOTHING_TO_DO:
                        return unpacker_output, self.RET_UNPACKER_NOTHING_TO_DO_OTHERS_OK
                    elif unpacker_rc >= self.UNPACKER_EXIT_CODE_UNPACKING_FAILED:
                        return unpacker_output, self.RET_UNPACKER_FAILED_OTHERS_OK
                else:
                    return unpacker_output, self.RET_UNPACK_OK
            else:
                # We cannot distinguish whether upx failed or the input file was
                # not upx-packed
                print('##### Unpacking by using UPX: nothing to do')
        else:
            print('##### \'upx\' not available: nothing to do')

        # Do not return -> try the next unpacker
        # Return.
        if unpacker_rc >= self.UNPACKER_EXIT_CODE_UNPACKING_FAILED:
            return unpacker_output, self.RET_UNPACKER_FAILED
        else:
            return unpacker_output, self.RET_NOTHING_TO_DO

    def unpack_all(self):
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
                if os.path.exists(tmp_output):
                    os.remove(tmp_output)
                break

        return (res_out, return_code) if res_rc == self.UNPACKER_EXIT_CODE_OTHER else (res_out, res_rc)


if __name__ == '__main__':
    unpacker = Unpacker(sys.argv[1:])
    _, rc = unpacker.unpack_all()
    sys.exit(rc)

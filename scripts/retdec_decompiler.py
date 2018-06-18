#!/usr/bin/env python3

"""Decompiles the given file into the selected target high-level language."""

import argparse
import glob
import hashlib
import os
import re
import shutil
import sys
import time

import retdec_config as config
from retdec_signature_from_library_creator import SigFromLib
from retdec_unpacker import Unpacker
from retdec_utils import Utils, CmdRunner


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument('input',
                        metavar='FILE',
                        help='File to decompile.')

    parser.add_argument('-a', '--arch',
                        dest='arch',
                        metavar='ARCH',
                        choices=['mips', 'pic32', 'arm', 'thumb', 'powerpc', 'x86'],
                        help='Specify target architecture [mips|pic32|arm|thumb|powerpc|x86].'
                             ' Required if it cannot be autodetected from the input (e.g. raw mode, Intel HEX).')

    parser.add_argument('-e', '--endian',
                        dest='endian',
                        metavar='ENDIAN',
                        choices=['little', 'big'],
                        help='Specify target endianness [little|big].'
                             ' Required if it cannot be autodetected from the input (e.g. raw mode, Intel HEX).')

    parser.add_argument('-k', '--keep-unreachable-funcs',
                        dest='keep_unreachable_funcs',
                        action='store_true',
                        help='Keep functions that are unreachable from the main function.')

    parser.add_argument('-l', '--target-language',
                        dest='hll',
                        default='c',
                        metavar='LANGUAGE',
                        choices=['c', 'py'],
                        help='Target high-level language [c|py].')

    parser.add_argument('-m', '--mode',
                        dest='mode',
                        metavar='MODE',
                        default='bin',
                        choices=['bin', 'll', 'raw'],
                        help='Force the type of decompilation mode [bin|ll|raw]'
                             '(default: ll if input\'s suffix is \'.ll\', bin otherwise).')

    parser.add_argument('-o', '--output',
                        dest='output',
                        metavar='FILE',
                        help='Output file.')

    parser.add_argument('-p', '--pdb',
                        dest='pdb',
                        metavar='FILE',
                        default='',
                        help='File with PDB debug information.')

    parser.add_argument('--generate-log',
                        dest='generate_log',
                        help='Generate log')

    parser.add_argument('--ar-index',
                        dest='ar_index',
                        metavar='INDEX',
                        help='Pick file from archive for decompilation by its zero-based index.')

    parser.add_argument('--ar-name',
                        dest='ar_name',
                        metavar='NAME',
                        help='Pick file from archive for decompilation by its name.')

    parser.add_argument('--backend-aggressive-opts',
                        dest='backend_aggressive_opts',
                        help='Enables aggressive optimizations.')

    parser.add_argument('--backend-arithm-expr-evaluator',
                        dest='backend_arithm_expr_evaluator',
                        default='c',
                        help='Name of the used evaluator of arithmetical expressions .')

    parser.add_argument('--backend-call-info-obtainer',
                        dest='backend_call_info_obtainer',
                        default='optim',
                        help='Name of the obtainer of information about function calls.')

    parser.add_argument('--backend-cfg-test',
                        dest='backend_cfg_test',
                        help='Unifies the labels of all nodes in the emitted CFG (this has to be used in tests).')

    parser.add_argument('--backend-disabled-opts',
                        dest='backend_disabled_opts',
                        help='Prevents the optimizations from the given'
                             ' comma-separated list of optimizations to be run.')

    parser.add_argument('--backend-emit-cfg',
                        dest='backend_emit_cfg',
                        help='Emits a CFG for each function in the backend IR (in the .dot format).')

    parser.add_argument('--backend-emit-cg',
                        dest='backend_emit_cg',
                        help='Emits a CG for the decompiled module in the backend IR (in the .dot format).')

    parser.add_argument('--backend-cg-conversion',
                        dest='backend_cg_conversion',
                        default='auto',
                        choices=['auto', 'manual'],
                        help='Should the CG from the backend be converted automatically into the desired format? '
                             '[auto|manual].')

    parser.add_argument('--backend-cfg-conversion',
                        dest='backend_cfg_conversion',
                        default='auto',
                        help='Should CFGs from the backend be converted automatically into the desired format?')

    parser.add_argument('--backend-enabled-opts',
                        dest='backend_enabled_opts',
                        help='Runs only the optimizations from the given comma-separated list of optimizations.')

    parser.add_argument('--backend-find-patterns',
                        dest='backend_find_patterns',
                        help='Runs the finders of patterns specified in the given comma-separated list '
                             '(use \'all\' to run them all).')

    parser.add_argument('--backend-force-module-name',
                        dest='backend_force_module_name',
                        help='Overwrites the module name that was detected/generated by the front-end.')

    parser.add_argument('--backend-keep-all-brackets',
                        dest='backend_keep_all_brackets',
                        help='Keeps all brackets in the generated code.')

    parser.add_argument('--backend-keep-library-funcs',
                        dest='backend_keep_library_funcs',
                        help='Keep functions from standard libraries.')

    parser.add_argument('--backend-llvmir2bir-converter',
                        dest='backend_llvmir2bir_converter',
                        default='orig',
                        help='Name of the converter from LLVM IR to BIR.')

    parser.add_argument('--backend-no-compound-operators',
                        dest='backend_no_compound_operators',
                        help='Do not emit compound operators (like +=) instead of assignments.')

    parser.add_argument('--backend-no-debug',
                        dest='backend_no_debug',
                        help='Disables the emission of debug messages, such as phases.')

    parser.add_argument('--backend-no-debug-comments',
                        dest='backend_no_debug_comments',
                        action='store_true',
                        help='Disables the emission of debug comments in the generated code.')

    parser.add_argument('--backend-no-opts',
                        dest='backend_no_opts',
                        action='store_true',
                        help='Disables backend optimizations.')

    parser.add_argument('--backend-no-symbolic-names',
                        dest='backend_no_symbolic_names',
                        action='store_true',
                        help='Disables the conversion of constant arguments to their symbolic names.')

    parser.add_argument('--backend-no-time-varying-info',
                        dest='backend_no_time_varying_info',
                        action='store_true',
                        help='Do not emit time-varying information, like dates.')

    parser.add_argument('--backend-no-var-renaming',
                        dest='backend_no_var_renaming',
                        action='store_true',
                        help='Disables renaming of variables in the backend.')

    parser.add_argument('--backend-semantics',
                        dest='backend_semantics',
                        help='A comma-separated list of the used semantics.')

    parser.add_argument('--backend-strict-fpu-semantics',
                        dest='backend_strict_fpu_semantics',
                        action='store_true',
                        help='Disables backend optimizations.')

    parser.add_argument('--backend-var-renamer',
                        dest='backend_var_renamer',
                        default='readable',
                        metavar='STYLE',
                        choices=['address', 'hungarian', 'readable', 'simple', 'unified'],
                        help='Used renamer of variables [address|hungarian|readable|simple|unified]')

    parser.add_argument('--cleanup',
                        dest='cleanup',
                        action='store_true',
                        help='Removes temporary files created during the decompilation.')

    parser.add_argument('--color-for-ida',
                        dest='color_for_ida',
                        action='store_true',
                        help='Put IDA Pro color tags to output C file.')

    parser.add_argument('--config',
                        dest='config_db',
                        help='Specify JSON decompilation configuration file.')

    parser.add_argument('--no-config',
                        dest='no_config',
                        action='store_true',
                        help='State explicitly that config file is not to be used.')

    parser.add_argument('--fileinfo-verbose',
                        dest='fileinfo_verbose',
                        action='store_true',
                        help='Print all detected information about input file.')

    parser.add_argument('--fileinfo-use-all-external-patterns',
                        dest='fileinfo_use_all_external_patterns',
                        action='store_true',
                        help='Use all detection rules from external YARA databases.')

    parser.add_argument('--graph-format',
                        dest='graph_format',
                        default='png',
                        metavar='FORMAT',
                        choices=['pdf', 'png', 'svg'],
                        help='Specify format of a all generated graphs (e.g. CG, CFG) [pdf|png|svg].')

    parser.add_argument('--raw-entry-point',
                        dest='raw_entry_point',
                        metavar='ADDRESS',
                        help='Entry point address used for raw binary (default: architecture dependent)')

    parser.add_argument('--raw-section-vma',
                        dest='raw_section_vma',
                        metavar='ADDRESS',
                        help='Virtual address where section created from the raw binary will be placed')

    parser.add_argument('--select-decode-only',
                        dest='selected_decode_only',
                        action='store_true',
                        help='Decode only selected parts (functions/ranges). Faster decompilation, but worse results.')

    parser.add_argument('--select-functions',
                        dest='selected_functions',
                        metavar='FUNCS',
                        help='Specify a comma separated list of functions to decompile (example: fnc1,fnc2,fnc3).')

    parser.add_argument('--select-ranges',
                        dest='selected_ranges',
                        metavar='RANGES',
                        help='Specify a comma separated list of ranges to decompile '
                             '(example: 0x100-0x200,0x300-0x400,0x500-0x600).')

    parser.add_argument('--stop-after',
                        dest='stop_after',
                        choices=['fileinfo', 'unpacker', 'bin2llvmir', 'llvmir2hll'],
                        help='Stop the decompilation after the given tool '
                             '(supported tools: fileinfo, unpacker, bin2llvmir, llvmir2hll).')

    parser.add_argument('--static-code-sigfile',
                        dest='static_code_sigfile',
                        default=[],
                        help='Adds additional signature file for static code detection.')

    parser.add_argument('--static-code-archive',
                        dest='static_code_archive',
                        default=[],
                        help='Adds additional signature file for static code detection from given archive.')

    parser.add_argument('--no-default-static-signatures',
                        dest='no_default_static_signatures',
                        action='store_true',
                        help='No default signatures for statically linked code analysis are loaded '
                             '(options static-code-sigfile/archive are still available).')

    parser.add_argument('--max-memory',
                        dest='max_memory',
                        help='Limits the maximal memory of fileinfo, unpacker, bin2llvmir, '
                             'and llvmir2hll into the given number of bytes.')

    parser.add_argument('--no-memory-limit',
                        dest='no_memory_limit',
                        action='store_true',
                        help='Disables the default memory limit (half of system RAM) of fileinfo, '
                             'unpacker, bin2llvmir, and llvmir2hll.')

    return parser.parse_args()


class Decompiler:
    def __init__(self, _args):
        self.args = _args
        self.timeout = 300
        self.input = ''
        self.output = ''
        self.config = ''
        self.selected_ranges = []
        self.selected_functions = []

        self.arch = ''
        self.out_unpacked = ''
        self.out_frontend_ll = ''
        self.out_frontend_bc = ''
        self.out_backend_bc = ''
        self.out_backend_ll = ''
        self.out_restored = ''
        self.out_archive = ''
        self.signatures_to_remove = []
        self.tool_log_file = ''

        self.TOOL_LOG_FILE = ''

    def check_arguments(self):
        """Check proper combination of input arguments.
            """

        global PICKED_FILE

        # Check whether the input file was specified.
        if not self.args.input:
            Utils.print_error('No input file was specified')
            return False

        if not os.access(self.args.input, os.R_OK):
            Utils.print_error('The input file \'%s\' does not exist or is not readable' % self.args.input)
            return False

        if self.args.max_memory:
            if self.args.no_memory_limit:
                Utils.print_error('Clashing options: --max-memory and --no-memory-limit')
                return False

            try:
                max_memory = int(self.args.max_memory)
                if max_memory > 0:
                    return True
            except ValueError:
                Utils.print_error(
                    'Invalid value for --max-memory: %s (expected a positive integer)' % self.args.max_memory)
                return False

        if self.args.static_code_archive:
            # User provided archive to create signature file from.
            if not os.path.isfile(self.args.static_code_archive):
                Utils.print_error('Invalid archive file \'%s\'' % self.args.static_code_archive)
                return False

        if self.args.static_code_sigfile:
            # User provided signature file.
            if not os.path.isfile(self.args.static_code_sigfile):
                Utils.print_error('Invalid .yara file \'%s\'' % self.args.static_code_sigfile)
                return False

        if self.args.selected_ranges:
            self.selected_ranges = self.args.selected_ranges.strip().split(',')
            self.args.keep_unreachable_funcs = True

            # Check that selected ranges are valid.
            for r in self.selected_ranges:
                # Check if valid range.
                if not Utils.is_range(r):
                    Utils.print_error(
                        'Range %s in option --select-ranges is not a valid decimal (e.g. 123-456) or hexadecimal '
                        '(e.g. 0x123-0xabc) range.' % r)
                    return False

                # Check if first <= last.
                ranges = r.split('-')
                # parser line into array
                if int(ranges[0]) > int(ranges[1]):
                    Utils.print_error(
                        'Range \'%s\' in option --select-ranges is not a valid range: '
                        'second address must be greater or equal than the first one.' % ranges)
                    return False

        if self.args.selected_functions:
            self.selected_functions = self.args.selected_functions.strip().split(',')
            self.args.keep_unreachable_funcs = True

        if self.args.no_config:
            if self.args.config_db:
                Utils.print_error('Option --no-config can not be used with option --config')
                return False

        if self.args.config_db:
            if not os.access(self.args.config_db, os.R_OK):
                Utils.print_error(
                    'The input JSON configuration file \'%s\' does not exist or is not readable' % self.args.config_db)
                return False

        if self.args.pdb:
            # File containing PDB debug information.
            if not os.access(self.args.pdb, os.R_OK):
                Utils.print_error('The input PDB file \'%s\' does not exist or is not readable' % self.args.pdb)
                return False

            self.args.pdb = os.path.abspath(self.args.pdb)

        # Try to detect desired decompilation mode if not set by user.
        # We cannot detect 'raw' mode because it overlaps with 'bin' (at least not based on extension).
        if not self.args.mode:
            if self.args.input.endswith('ll'):
                # Suffix .ll
                self.args.mode = 'll'
            else:
                self.args.mode = 'bin'

        # Print warning message about unsupported combinations of options.
        if self.args.mode == 'll':
            if self.args.arch:
                Utils.print_warning('Option -a|--arch is not used in mode ' + self.args.mode)

            if self.args.pdb:
                Utils.print_warning('Option -p|--pdb is not used in mode ' + self.args.mode)

            if not self.args.config_db or not self.args.no_config:
                Utils.print_error('Option --config or --no-config must be specified in mode ' + self.args.mode)
                return False

        elif self.args.mode == 'raw':
            # Errors -- missing critical arguments.
            if not self.args.arch:
                Utils.print_error('Option -a|--arch must be used with mode ' + self.args.mode)
                return False

            if not self.args.endian:
                Utils.print_error('Option -e|--endian must be used with mode ' + self.args.mode)
                return False

            if not self.args.raw_entry_point:
                Utils.print_error('Option --raw-entry-point must be used with mode ' + self.args.mode)
                return False

            if not self.args.raw_section_vma:
                Utils.print_error('Option --raw-section-vma must be used with mode ' + self.args.mode)
                return False

            if not Utils.is_number(self.args.raw_entry_point):
                Utils.print_error(
                    'Value in option --raw-entry-point must be decimal (e.g. 123) or hexadecimal value (e.g. 0x123)')
                return False

            if not Utils.is_number(self.args.raw_section_vma):
                Utils.print_error(
                    'Value in option --raw-section-vma must be decimal (e.g. 123) or hexadecimal value (e.g. 0x123)')
                return False

        # Archive decompilation errors.
        if self.args.ar_name and self.args.ar_index:
            Utils.print_error('Options --ar-name and --ar-index are mutually exclusive. Pick one.')
            return False

        if self.args.mode != 'bin':
            if self.args.ar_name:
                Utils.print_warning('Option --ar-name is not used in mode ' + self.args.mode)

            if self.args.ar_index:
                Utils.print_warning('Option --ar-index is not used in mode ' + self.args.mode)

        if not self.args.output:
            # No output file was given, so use the default one.
            input_name = self.args.input
            if input_name.endswith('ll'):
                # Suffix .ll
                self.output = input_name[:-2] + self.args.hll
            elif input_name.endswith('exe'):
                # Suffix .exe
                self.output = input_name[:-3] + self.args.hll
            elif input_name.endswith('elf'):
                # Suffix .elf
                self.output = input_name[:-3] + self.args.hll
            elif input_name.endswith('ihex'):
                # Suffix .ihex
                self.output = input_name[:-4] + self.args.hll
            elif input_name.endswith('macho'):
                # Suffix .macho
                self.output = input_name[:-5] + self.args.hll
            else:
                self.output = self.output + PICKED_FILE + '.' + self.args.hll

        # If the output file name matches the input file name, we have to change the
        # output file name. Otherwise, the input file gets overwritten.
        if self.args.input == self.output:
            self.output = self.args.input + '.out.' + self.args.hll

        # Convert to absolute paths.
        self.input = os.path.abspath(self.args.input)
        self.output = os.path.abspath(self.output)

        if self.args.arch:
            self.arch = self.args.arch

        return True

    def print_warning_if_decompiling_bytecode(self):
        """Prints a warning if we are decompiling bytecode."""

        cmd = CmdRunner()
        bytecode, _, _ = cmd.run_cmd([config.CONFIGTOOL, self.config, '--read', '--bytecode'])
        # bytecode = os.popen('\'' + config.CONFIGTOOL + '\' \'' + CONFIG + '\' --read --bytecode').read().rstrip('\n')

        if bytecode != '':
            Utils.print_warning(
                'Detected %s bytecode, which cannot be decompiled by our machine-code decompiler.'
                ' The decompilation result may be inaccurate.' % bytecode)

    def check_whether_decompilation_should_be_forcefully_stopped(self, tool_name):
        """Checks whether the decompilation should be forcefully stopped because of the
        --stop-after parameter. If so, self.cleanup is run and the script exits with 0.
        Arguments:
          $1 Name of the tool.
        The function expects the $STOP_AFTER variable to be set.
        """

        if self.args.stop_after == tool_name:
            if self.args.generate_log:
                self.generate_log()

            self.cleanup()
            print()
            print('#### Forced stop due to  - -stop - after %s...' % self.args.stop_after)
            return True
        return False

    def cleanup(self):
        """Cleanup working directory"""

        if self.args.cleanup:
            Utils.remove_dir_forced(self.out_unpacked)
            Utils.remove_dir_forced(self.out_frontend_ll)
            Utils.remove_dir_forced(self.out_frontend_bc)

            if self.config != self.args.config_db:
                Utils.remove_dir_forced(self.config)

            Utils.remove_dir_forced(self.out_backend_bc)
            Utils.remove_dir_forced(self.out_backend_ll)
            Utils.remove_dir_forced(self.out_restored)

            # Archive support
            Utils.remove_dir_forced(self.out_archive)

            # Archive support (Macho-O Universal)
            for sig in self.signatures_to_remove:
                Utils.remove_dir_forced(sig)

            # Signatures generated from archives
            if self.TOOL_LOG_FILE:
                Utils.remove_dir_forced(self.TOOL_LOG_FILE)

    def generate_log(self):
        """
        LOG_FILE = self.output + '.decompilation.log'
        LOG_DECOMPILATION_END_DATE = time.strftime('%S')

        LOG_FILEINFO_OUTPUT = self.json_escape(LOG_FILEINFO_OUTPUT)
        LOG_UNPACKER_OUTPUT = self.json_escape(LOG_UNPACKER_OUTPUT)
        LOG_BIN2LLVMIR_OUTPUT = self.remove_colors(LOG_BIN2LLVMIR_OUTPUT)
        LOG_BIN2LLVMIR_OUTPUT = self.json_escape(LOG_BIN2LLVMIR_OUTPUT)
        LOG_LLVMIR2HLL_OUTPUT = self.remove_colors(LOG_LLVMIR2HLL_OUTPUT)
        LOG_LLVMIR2HLL_OUTPUT = self.json_escape(LOG_LLVMIR2HLL_OUTPUT)

        log_structure = '{\n\t\'input_file\' : \'%s\',\n\t\'pdb_file\' : \'%s\',\n\t\'start_date\' :' \
                        ' \'%s\',\n\t\'end_date\' : \'%s\',\n\t\'mode\' : \'%s\',\n\t\'arch\' : \'%s\',\n\t\'format\'' \
                        ' : \'%s\',\n\t\'fileinfo_rc\' : \'%s\',\n\t\'unpacker_rc\' : \'%s\',\n\t\'bin2llvmir_rc\'' \
                        ' : \'%s\',\n\t\'llvmir2hll_rc\' : \'%s\',\n\t\'fileinfo_output\' :' \
                        ' \'%s\',\n\t\'unpacker_output\' : \'%s\',\n\t\'bin2llvmir_output\' :' \
                        ' \'%s\',\n\t\'llvmir2hll_output\' : \'%s\',\n\t\'fileinfo_runtime\' :' \
                        ' \'%s\',\n\t\'bin2llvmir_runtime\' : \'%s\',\n\t\'llvmir2hll_runtime\' :' \
                        ' \'%s\',\n\t\'fileinfo_memory\' : \'%s\',\n\t\'bin2llvmir_memory\' :' \
                        ' \'%s\',\n\t\'llvmir2hll_memory\' : \'%s\'\n}\n'

        print(log_structure % (
            self.input, self.args.pdb, LOG_DECOMPILATION_START_DATE, LOG_DECOMPILATION_END_DATE, self.args.mode,
            self.args.arch,
            FORMAT, LOG_FILEINFO_RC, LOG_UNPACKER_RC, LOG_BIN2LLVMIR_RC, LOG_LLVMIR2HLL_RC,
            LOG_FILEINFO_OUTPUT, LOG_UNPACKER_OUTPUT, LOG_BIN2LLVMIR_OUTPUT, LOG_LLVMIR2HLL_OUTPUT,
            LOG_FILEINFO_RUNTIME, LOG_BIN2LLVMIR_RUNTIME, LOG_LLVMIR2HLL_RUNTIME, LOG_FILEINFO_MEMORY,
            LOG_BIN2LLVMIR_MEMORY, LOG_LLVMIR2HLL_MEMORY))
        """

    #
    # Parses the given return code and output from a tool that was run through
    # `/usr/bin/time -v` and prints the return code to be stored into the log.
    #
    # Parameters:
    #
    #    - $1: return code from `/usr/bin/time`
    #    - $2: combined output from the tool and `/usr/bin/time -v`
    #
    # This function has to be called for every tool that is run through
    # `/usr/bin/time`. The reason is that when a tool is run without
    # `/usr/bin/time` and it e.g. segfaults, shell returns 139, but when it is run
    # through `/usr/bin/time`, it returns 11 (139 - 128). If this is the case, this
    # function prints 139 instead of 11 to make the return codes of all tools
    # consistent.
    #
    def get_tool_rc(self, return_code, output):
        global BASH_REMATCH
        global RC

        orig_rc = return_code
        signal_regex = 'Command terminated by signal ([0-9]*)'

        if re.search(signal_regex, output):
            signal_num = BASH_REMATCH[1]
            RC = signal_num + 128
        else:
            RC = orig_rc
            # We want to be able to distinguish assertions and memory-insufficiency
            # errors. The problem is that both assertions and memory-insufficiency
            # errors make the program exit with return code 134. We solve this by
            # replacing 134 with 135 (SIBGUS, 7) when there is 'std::bad_alloc' in the
            # output. So, 134 will mean abort (assertion error) and 135 will mean
            # memory-insufficiency error.
            if RC == 134 or re.search('std::bad_alloc', output):
                RC = 135
            print(RC)

        return RC

    #
    # Parses the given output ($1) from a tool that was run through
    # `/usr/bin/time -v` and prints the memory usage in MB.
    #
    def get_tool_memory_usage(self, tool):
        """The output from `/usr/bin/time -v` looks like this:

            [..] (output from the tool)
                Command being timed: 'tool'
                [..] (other data)
                Maximum resident set size (kbytes): 1808
                [..] (other data)

        We want the value of 'resident set size' (RSS), which we convert from KB
        to MB. If the resulting value is less than 1 MB, round it to 1 MB.
        """
        _, _, tail = tool.partition('Maximum resident set size (kbytes): ')
        rss_kb = tail.split(' ')[0]
        rss_mb = (rss_kb / 1024)

        return rss_mb if (rss_mb > 0) else 1

    #
    # Prints an escaped version of the given text so it can be inserted into JSON.
    #
    # Parameters:
    #   - $1 Text to be escaped.
    #
    def json_escape(self, text):
        # We need to escape backslashes (\), double quotes ('), and replace new lines with '\n'.

        return re.escape(text)

    def remove_colors(self, text):
        """Removes color codes from the given text ($1).
        """
        # _rc0 = subprocess.Popen('sed' + ' ' + '-r' + ' ' + 's/\x1b[^m]*m//g', shell=True, stdin=subprocess.PIPE)

        res = re.compile(r's/\x1b[^m]*m//g')
        return res.sub('', text)

    def string_to_md5(self, string):
        """Generate a MD5 checksum from a given string.
        """
        m = hashlib.md5()
        m.update(string)

        return m.hexdigest()

    def decompile(self):
        cmd = CmdRunner()

        # Check arguments and set default values for unset options.
        if not self.check_arguments():
            return 1

        # Initialize variables used by logging.
        if self.args.generate_log:
            log_decompilation_start_date = time.strftime('%s')  # os.popen('date  + %s').read().rstrip('\n')
            # Put the tool log file and tmp file into /tmp because it uses tmpfs. This means that
            # the data are stored in RAM instead on the disk, which should provide faster access.
            tmp_dir = '/tmp/decompiler_log'
            os.makedirs(tmp_dir, exist_ok=True)
            file_md5 = self.string_to_md5(self.output)
            tool_log_file = tmp_dir + '/' + file_md5 + '.tool'

        # Raw.
        if self.args.mode == 'raw':
            # Entry point for THUMB must be odd.
            if self.args.arch == 'thumb' or (self.args.raw_entry_point % 2) == 0:
                self.args.raw_entry_point = (self.args.raw_entry_point + 1)

            self.args.keep_unreachable_funcs = True

        # Check for archives.
        if self.args.mode == 'bin':
            # Check for archives packed in Mach-O Universal Binaries.
            print('##### Checking if file is a Mach-O Universal static library...')
            print('RUN: ' + config.EXTRACT + ' --list ' + self.input)

            if Utils.is_macho_archive(self.input):
                out_archive = self.output + '.a'
                if self.arch:
                    print()
                    print('##### Restoring static library with architecture family ' + self.args.arch + '...')
                    print(
                        'RUN: ' + config.EXTRACT + ' --family ' + self.args.arch + ' --out ' + out_archive + ' ' + self.input)

                    _, extract_rc, _ = cmd.run_cmd(
                        [config.EXTRACT, '--family', self.args.arch, '--out', out_archive, self.input])
                    if not extract_rc:
                        # Architecture not supported
                        print('Invalid --arch option \'' + self.args.arch +
                              '\'. File contains these architecture families:')
                        cmd.run_cmd([config.EXTRACT, '--list', self.input])
                        self.cleanup()
                        # sys.exit(1)
                        return 1
                else:
                    # Pick best architecture
                    print()
                    print('##### Restoring best static library for decompilation...')
                    print('RUN: ' + config.EXTRACT + ' --best --out ' + out_archive + ' ' + self.input)
                    cmd.run_cmd([config.EXTRACT, '--best', '--out', out_archive, self.input])

                self.input = out_archive

            print()
            print('##### Checking if file is an archive...')
            print('RUN: ' + config.AR + ' --arch-magic ' + self.input)

            if Utils.has_archive_signature(self.input):
                print('This file is an archive!')

                # Check for thin signature.
                if Utils.has_thin_archive_signature(self.input):
                    self.cleanup()
                    Utils.print_error('File is a thin archive and cannot be decompiled.')
                    return 1

                # Check if our tools can handle it.
                if not Utils.is_valid_archive(self.input):
                    self.cleanup()
                    Utils.print_error('The input archive has invalid format.')
                    return 1

                # Get and check number of objects.
                arch_object_count = Utils.archive_object_count(self.input)
                if arch_object_count <= 0:
                    self.cleanup()
                    Utils.print_error('The input archive is empty.')
                    return 1

                # Prepare object output path.
                out_restored = self.output + '.restored'

                # Pick object by index.
                if self.args.ar_index:
                    print()
                    print('##### Restoring object file on index '' + (self.args.ar_index) + '' from archive...')
                    print('RUN: ' + config.AR + ' ' + self.input + ' --index ' + self.args.ar_index + ' --output '
                          + out_restored)

                    if not Utils.archive_get_by_index(self.input, self.args.ar_index, out_restored):
                        self.cleanup()
                        valid_index = (arch_object_count - 1)

                        if valid_index != 0:
                            Utils.print_error('File on index \'' + self.args.ar_index
                                              + '\' was not found in the input archive. Valid indexes are 0-' + (
                                                  valid_index) + '.')
                            return 1
                        else:
                            Utils.print_error('File on index \'' + self.args.ar_index +
                                              '\' was not found in the input archive. The only valid index is 0.')
                            return 1

                    self.input = out_restored
                # Pick object by name
                elif self.args.ar_name:
                    print()
                    print('##### Restoring object file with name '' + (self.args.ar_name) + '' from archive...')
                    print('RUN: ' + config.AR + ' ' + self.input + ' --name ' + self.args.ar_name + ' --output '
                          + out_restored)

                    if not Utils.archive_get_by_name(self.input, self.args.ar_name, out_restored):
                        self.cleanup()
                        Utils.print_error('File named %s was not found in the input archive.' % self.args.ar_name)
                        return 1

                    self.input = out_restored
                else:
                    # Print list of files.
                    print('Please select file to decompile with either \' --ar-index=n\'')
                    print('or \' --ar-name=string\' option. Archive contains these files:')

                    Utils.archive_list_numbered_content(self.input)
                    self.cleanup()
                    return 1
            else:
                if self.args.ar_name:
                    Utils.print_warning('Option --ar-name can be used only with archives.')

                if self.args.ar_index:
                    Utils.print_warning('Option --ar-index can be used only with archives.')

                print('Not an archive, going to the next step.')

        if self.args.mode in ['bin', 'raw']:
            # Assignment of other used variables.
            name = os.path.splitext(self.output)[0]
            out_frontend = self.output + '.frontend'
            self.out_unpacked = name + '-unpacked'
            self.out_frontend_ll = out_frontend + '.ll'
            self.out_frontend_bc = out_frontend + '.bc'
            self.config = self.output + '.json'

            if self.config != self.args.config_db:
                Utils.remove_file_forced(self.config)

            if self.args.config_db:
                shutil.copyfile(self.args.config_db, self.config)

            # Preprocess existing file or create a new, empty JSON file.
            if os.path.isfile(self.config):
                cmd.run_cmd([config.CONFIGTOOL, self.config, '--preprocess'])
            else:
                with open(self.config, 'w') as f:
                    f.write('{}')

            # Raw data needs architecture, endianess and optionaly sections's vma and entry point to be specified.
            if self.args.mode == 'raw':
                if not self.arch or self.arch == 'unknown' or self.arch == '':
                    Utils.print_error('Option -a|--arch must be used with mode ' + self.args.mode)
                    return 1

                if not self.args.endian:
                    Utils.print_error('Option -e|--endian must be used with mode ' + self.args.mode)
                    return 1

                cmd.run_cmd([config.CONFIGTOOL, self.config, '--write', '--format', 'raw'])
                cmd.run_cmd([config.CONFIGTOOL, self.config, '--write', '--arch', self.arch])
                cmd.run_cmd([config.CONFIGTOOL, self.config, '--write', '--bit-size', '32'])
                cmd.run_cmd([config.CONFIGTOOL, self.config, '--write', '--file-class', '32'])
                cmd.run_cmd([config.CONFIGTOOL, self.config, '--write', '--endian', self.args.endian])

                if self.args.raw_entry_point:
                    cmd.run_cmd([config.CONFIGTOOL, self.config, '--write', '--entry-point', self.args.raw_entry_point])

                if self.args.raw_section_vma:
                    cmd.run_cmd([config.CONFIGTOOL, self.config, '--write', '--section-vma', self.args.raw_section_vma])

            #
            # Call fileinfo to create an initial config file.
            #
            fileinfo_params = ['-c', self.config, '--similarity', self.input, '--no-hashes=all']

            if self.args.fileinfo_verbose:
                fileinfo_params = ['-c', self.config, '--similarity', '--verbose', self.input]

            for par in config.FILEINFO_EXTERNAL_YARA_PRIMARY_CRYPTO_DATABASES:
                fileinfo_params.extend(['--crypto', par])

            if self.args.fileinfo_use_all_external_patterns:
                for par in config.FILEINFO_EXTERNAL_YARA_EXTRA_CRYPTO_DATABASES:
                    fileinfo_params.extend(['--crypto', par])

            if self.args.max_memory:
                fileinfo_params.extend(['--max-memory', self.args.max_memory])
            elif not self.args.no_memory_limit:
                # By default, we want to limit the memory of fileinfo into half of
                # system RAM to prevent potential black screens on Windows (#270).
                fileinfo_params.append('--max-memory-half-ram')

            print()
            print('##### Gathering file information...')
            print('RUN: ' + config.FILEINFO + ' ' + ' '.join(fileinfo_params))

            fileinfo_rc = 0

            if self.args.generate_log:
                """
                tcmd = TimeMeasuredProcess()
                LOG_FILEINFO_OUTPUT, fileinfo_rc, LOG_FILEINFO_RUNTIME = \
                    tcmd.run_cmd([config.FILEINFO] + fileinfo_params)

                LOG_FILEINFO_MEMORY = self.get_tool_memory_usage(LOG_FILEINFO_OUTPUT)
                print(LOG_FILEINFO_OUTPUT)
                """
                pass
            else:
                fileinfo, fileinfo_rc, _ = cmd.run_cmd([config.FILEINFO, *fileinfo_params])
                print(fileinfo)

            if fileinfo_rc != 0:
                if self.args.generate_log:
                    self.generate_log()

                self.cleanup()
                # The error message has been already reported by fileinfo in stderr.
                Utils.print_error('')
                return 1

            if self.check_whether_decompilation_should_be_forcefully_stopped('fileinfo'):
                return 0

            #
            # Unpacking.
            #
            unpack_params = ['--extended-exit-codes', '--output', self.out_unpacked, self.input]

            if self.args.max_memory:
                unpack_params.extend(['--max-memory', self.args.max_memory])
            elif not self.args.no_memory_limit:
                # By default, we want to limit the memory of retdec-unpacker into half
                # of system RAM to prevent potential black screens on Windows (#270).
                unpack_params.append('--max-memory-half-ram')

            unpacker = Unpacker(unpack_params)
            if self.args.generate_log:
                # we should get the output from the unpacker tool
                log_unpacker_output, unpacker_rc = unpacker.unpack_all()
                LOG_UNPACKER_RC = unpacker_rc
            else:
                _, unpacker_rc = unpacker.unpack_all()

            if self.check_whether_decompilation_should_be_forcefully_stopped('unpacker'):
                return 0

            # RET_UNPACK_OK=0
            # RET_UNPACKER_NOTHING_TO_DO_OTHERS_OK=1
            # RET_NOTHING_TO_DO=2
            # RET_UNPACKER_FAILED_OTHERS_OK=3
            # RET_UNPACKER_FAILED=4
            if unpacker_rc == Unpacker.RET_UNPACK_OK or unpacker_rc == Unpacker.RET_UNPACKER_NOTHING_TO_DO_OTHERS_OK \
                    or unpacker_rc == Unpacker.RET_UNPACKER_FAILED_OTHERS_OK:

                # Successfully unpacked -> re-run fileinfo to obtain fresh information.
                self.input = self.out_unpacked
                fileinfo_params = ['-c', self.config, '--similarity', self.input, '--no-hashes=all']

                if self.args.fileinfo_verbose:
                    fileinfo_params = ['-c', self.config, '--similarity', '--verbose', self.input]

                for pd in config.FILEINFO_EXTERNAL_YARA_PRIMARY_CRYPTO_DATABASES:
                    fileinfo_params.extend(['--crypto', pd])

                if self.args.fileinfo_use_all_external_patterns:
                    for ed in config.FILEINFO_EXTERNAL_YARA_EXTRA_CRYPTO_DATABASES:
                        fileinfo_params.extend(['--crypto', ed])

                if self.args.max_memory:
                    fileinfo_params.extend(['--max-memory', self.args.max_memory])
                elif not self.args.no_memory_limit:
                    # By default, we want to limit the memory of fileinfo into half of
                    # system RAM to prevent potential black screens on Windows (#270).
                    fileinfo_params.append('--max-memory-half-ram')

                print()
                print('##### Gathering file information after unpacking...')
                print('RUN: ' + config.FILEINFO + ' ' + ' '.join(fileinfo_params))

                if self.args.generate_log:
                    """
                    FILEINFO_AND_TIME_OUTPUT = os.popen(
                        TIME + ' \'' + config.FILEINFO + '\' \'' + ' '.join(fileinfo_params) + '\' 2>&1').read().rstrip(
                        '\n')

                    fileinfo_rc = 0  # _rc0

                    tcmd = TimeMeasuredProcess()
                    LOG_FILEINFO_OUTPUT, fileinfo_rc, LOG_FILEINFO_RUNTIME = \
                        tcmd.run_cmd([config.FILEINFO] + fileinfo_params)

                    LOG_FILEINFO_RUNTIME = (LOG_FILEINFO_RUNTIME + FILEINFO_RUNTIME)
                    FILEINFO_MEMORY = self.get_tool_memory_usage(FILEINFO_AND_TIME_OUTPUT)
                    LOG_FILEINFO_MEMORY = (LOG_FILEINFO_MEMORY + FILEINFO_MEMORY) / 2
                    LOG_FILEINFO_OUTPUT = self.get_tool_output(FILEINFO_AND_TIME_OUTPUT)
                    print(LOG_FILEINFO_OUTPUT)
                    """
                    pass
                else:
                    fileinfo, fileinfo_rc, _ = cmd.run_cmd([config.FILEINFO, *fileinfo_params])
                    print(fileinfo)

                if fileinfo_rc != 0:
                    if self.args.generate_log:
                        self.generate_log()

                    self.cleanup()
                    # The error message has been already reported by fileinfo in stderr.
                    Utils.print_error('')
                    return 1

                self.print_warning_if_decompiling_bytecode()

            # Check whether the architecture was specified.
            if self.arch:
                cmd.run_cmd([config.CONFIGTOOL, self.config, '--write', '--arch', self.arch])
            else:
                # Get full name of the target architecture including comments in parentheses
                arch_full, _, _ = cmd.run_cmd([config.CONFIGTOOL, self.config, '--read', '--arch'])
                arch_full = arch_full.lower()

                # Strip comments in parentheses and all trailing whitespace
                self.arch = arch_full.strip()

            # Get object file format.
            fileformat, _, _ = cmd.run_cmd([config.CONFIGTOOL, self.config, '--read', '--format'])
            fileformat = fileformat.lower()

            # Intel HEX needs architecture to be specified
            if fileformat in ['ihex']:
                if not self.arch or self.arch == 'unknown':
                    Utils.print_error('Option -a|--arch must be used with format ' + fileformat)
                    return 1

                if not self.args.endian:
                    Utils.print_error('Option -e|--endian must be used with format ' + fileformat)
                    return 1

                cmd.run_cmd([config.CONFIGTOOL, self.config, '--write', '--arch', self.arch])
                cmd.run_cmd([config.CONFIGTOOL, self.config, '--write', '--bit-size', '32'])
                cmd.run_cmd([config.CONFIGTOOL, self.config, '--write', '--file-class', '32'])
                cmd.run_cmd([config.CONFIGTOOL, self.config, '--write', '--endian', self.args.endian])

            ords_dir = ''
            # Check whether the correct target architecture was specified.
            if self.arch in ['arm', 'thumb']:
                ords_dir = config.ARM_ORDS_DIR
            elif self.arch in ['x86']:
                ords_dir = config.X86_ORDS_DIR
            elif self.arch in ['powerpc', 'mips', 'pic32']:
                pass
            else:
                # nothing
                if self.args.generate_log:
                    self.generate_log()

                self.cleanup()
                Utils.print_error('Unsupported target architecture %s. Supported architectures: '
                                  'Intel x86, ARM, ARM + Thumb, MIPS, PIC32, PowerPC.' % self.arch)
                return 1

            # Check file class (e.g. 'ELF32', 'ELF64'). At present, we can only decompile 32-bit files.
            # Note: we prefer to report the 'unsupported architecture' error (above) than this 'generic' error.
            fileclass, _, _ = cmd.run_cmd([config.CONFIGTOOL, self.config, '--read', '--file-class'])

            if fileclass not in ['16', '32']:
                if self.args.generate_log:
                    self.generate_log()

                self.cleanup()
                Utils.print_error(
                    'Unsupported target format \'%s%s\'. Supported formats: ELF32, PE32, Intel HEX 32, Mach-O 32.' % (
                        format, fileclass))
                return 1

            # Set path to statically linked code signatures.
            #
            # TODO: Using ELF for IHEX is ok, but for raw, we probably should somehow decide between ELF and PE,
            # or use both, for RAW.
            sig_format = fileformat

            if sig_format in ['ihex', 'raw']:
                sig_format = 'elf'

            endian_result, _, _ = cmd.run_cmd([config.CONFIGTOOL, self.config, '--read', '--endian'])

            if endian_result == 'little':
                sig_endian = 'le'
            elif endian_result == 'big':
                sig_endian = 'be'
            else:
                if self.args.generate_log:
                    self.generate_log()

                self.cleanup()
                Utils.print_error('Cannot determine endiannesss.')
                return 1

            sig_arch = self.arch

            if sig_arch == 'pic32':
                sig_arch = 'mips'

            signatures_dir = os.path.join(config.GENERIC_SIGNATURES_DIR, sig_format, fileclass, sig_endian, sig_arch)

            self.print_warning_if_decompiling_bytecode()

            # Decompile unreachable functions.
            if self.args.keep_unreachable_funcs:
                cmd.run_cmd([config.CONFIGTOOL, self.config, '--write', '--keep-unreachable-funcs', 'true'])

            if self.args.static_code_archive:
                # Get signatures from selected archives.
                if len(self.args.static_code_archive) > 0:
                    print()
                    print('##### Extracting signatures from selected archives...')

                lib_index = 0
                for lib in self.args.static_code_archive:

                    print('Extracting signatures from file \'%s\'', lib)
                    # TODO replace command
                    crop_arch_path, _, _ = cmd.run_cmd(
                        'basename \'' + lib + '\' | LC_ALL=C sed -e \'s/[^A-Za-z0-9_.-]/_/g\'')
                    sig_out = self.output + '.' + crop_arch_path + '.' + lib_index + '.yara'

                    # Call sig from lib tool
                    sig_from_lib = SigFromLib([lib, '--output', sig_out])
                    if sig_from_lib.run():
                        cmd.run_cmd([config.CONFIGTOOL, self.config, '--write', '--user-signature', sig_out])
                        self.signatures_to_remove.append(sig_out)
                    else:
                        Utils.print_warning('Failed extracting signatures from file \'' + lib + '\'')

                    lib_index += 1

            # Store paths of signature files into config for frontend.
            if not self.args.no_default_static_signatures:
                cmd.run_cmd([config.CONFIGTOOL, self.config, '--write', '--signatures', signatures_dir])

            # User provided signatures.
            if self.args.static_code_sigfile:
                for i in self.args.static_code_sigfile:
                    cmd.run_cmd([config.CONFIGTOOL, self.config, '--write', '--user-signature', i])

            # Store paths of type files into config for frontend.
            if os.path.isdir(config.GENERIC_TYPES_DIR):
                cmd.run_cmd([config.CONFIGTOOL, self.config, '--write', '--types', config.GENERIC_TYPES_DIR])

            # Store path of directory with ORD files into config for frontend (note: only directory,
            # not files themselves).
            if os.path.isdir(ords_dir):
                cmd.run_cmd([config.CONFIGTOOL, self.config, '--write', '--ords', ords_dir + os.path.sep])

            # Store paths to file with PDB debugging information into config for frontend.
            if self.args.pdb:
                cmd.run_cmd([config.CONFIGTOOL, self.config, '--write', '--pdb-file', self.args.pdb])

            # Store file names of input and output into config for frontend.
            cmd.run_cmd([config.CONFIGTOOL, self.config, '--write', '--input-file', self.input])
            cmd.run_cmd([config.CONFIGTOOL, self.config, '--write', '--frontend-output-file', self.out_frontend_ll])
            cmd.run_cmd([config.CONFIGTOOL, self.config, '--write', '--output-file', self.output])

            # Store decode only selected parts flag.
            if self.args.selected_decode_only:
                cmd.run_cmd([config.CONFIGTOOL, self.config, '--write', '--decode-only-selected', 'true'])
            else:
                cmd.run_cmd([config.CONFIGTOOL, self.config, '--write', '--decode-only-selected', 'false'])

            # Store selected functions or selected ranges into config for frontend.
            if self.args.selected_functions:
                for f in self.args.selected_functions:
                    cmd.run_cmd([config.CONFIGTOOL, self.config, '--write', '--selected-func', f])

            if self.args.selected_ranges:
                for r in self.args.selected_ranges:
                    cmd.run_cmd([config.CONFIGTOOL, self.config, '--write', '--selected-range', r])

            # Assignment of other used variables.
            # We have to ensure that the .bc version of the decompiled .ll file is placed
            # in the same directory as are other output files. Otherwise, there may be
            # race-condition problems when the same input .ll file is decompiled in
            # parallel processes because they would overwrite each other's .bc file. This
            # is most likely to happen in regression tests in the 'll' mode.
            out_backend = self.output + '.backend'

            # If the input file is the same as $OUT_BACKEND_LL below, then we have to change the name of
            # $OUT_BACKEND. Otherwise, the input file would get overwritten during the conversion.
            if self.out_frontend_ll == out_backend + '.ll':
                out_backend = self.output + '.backend.backend'

            self.out_backend_bc = out_backend + '.bc'
            self.out_backend_ll = out_backend + '.ll'

            #
            # Decompile the binary into LLVM IR.
            #
            bin2llvmir_params = config.BIN2LLVMIR_PARAMS

            if self.args.keep_unreachable_funcs:
                # Prevent bin2llvmir from removing unreachable functions.
                bin2llvmir_params.remove('-unreachable-funcs')

            if self.config == '' and self.args.config_db:
                self.config = self.args.config_db

            bin2llvmir_params.extend(['-config-path', self.config])

            if self.args.max_memory:
                bin2llvmir_params.extend(['-max-memory', self.args.max_memory])
            elif not self.args.no_memory_limit:
                # By default, we want to limit the memory of bin2llvmir into half of
                # system RAM to prevent potential black screens on Windows (#270).
                bin2llvmir_params.append('-max-memory-half-ram')

            print()
            print('##### Decompiling ' + self.input + ' into ' + self.out_backend_bc + '...')
            print('RUN: ' + config.BIN2LLVMIR + ' ' + ' '.join(bin2llvmir_params) + ' -o ' + self.out_backend_bc)

            bin2llvmir_rc = 0

            if self.args.generate_log:
                """
                PID = 0
                bin2llvmir_rc = 0

                def thread1():
                    subprocess.call([TIME, config.BIN2LLVMIR, ' '.join(bin2llvmir_params), '-o',
                        self.out_backend_bc], shell=True, stdout=open(tool_log_file, 'wb'), stderr=subprocess.STDOUT)

                    threading.Thread(target=thread1).start()

                    PID = 0  # TODO $! Expand.exclamation()

                def thread2():
                    self.timed_kill(PID)

                threading.Thread(target=thread2).start()

                # subprocess.call(['wait', PID], shell=True, stderr=subprocess.STDOUT, stdout=subprocess.DEVNULL)
                os.kill(PID, 0)

                bin2llvmir_rc = 0  # TODO use rc _rc2
                BIN2LLVMIR_AND_TIME_OUTPUT = os.popen('cat \'' + tool_log_file + '\'').read().rstrip('\n')
                LOG_BIN2LLVMIR_RC = self.get_tool_rc(bin2llvmir_rc, BIN2LLVMIR_AND_TIME_OUTPUT)
                LOG_BIN2LLVMIR_RUNTIME = self.get_tool_runtime(BIN2LLVMIR_AND_TIME_OUTPUT)
                LOG_BIN2LLVMIR_MEMORY = self.get_tool_memory_usage(BIN2LLVMIR_AND_TIME_OUTPUT)
                LOG_BIN2LLVMIR_OUTPUT = self.get_tool_output(BIN2LLVMIR_AND_TIME_OUTPUT)
                print(LOG_BIN2LLVMIR_OUTPUT, end='')
                """
            else:
                bin22llvmir_out, bin2llvmir_rc, _ = cmd.run_cmd([config.BIN2LLVMIR, *bin2llvmir_params, '-o',
                                                                 self.out_backend_bc])
                print(bin22llvmir_out)

            if bin2llvmir_rc != 0:
                if self.args.generate_log:
                    self.generate_log()

                self.cleanup()
                Utils.print_error('Decompilation to LLVM IR failed')
                return 1

            if self.check_whether_decompilation_should_be_forcefully_stopped('bin2llvmir'):
                return 0
        # modes 'bin' || 'raw'

        # LL mode goes straight to backend.
        if self.args.mode == 'll':
            self.out_backend_bc = self.input
            self.config = self.args.config_db

        # Create parameters for the $LLVMIR2HLL call.
        llvmir2hll_params = ['-target-hll=' + self.args.hll, '-var-renamer=' + self.args.backend_var_renamer,
                             '-var-name-gen=fruit', '-var-name-gen-prefix=',
                             '-call-info-obtainer=' + self.args.backend_call_info_obtainer,
                             '-arithm-expr-evaluator=' + self.args.backend_arithm_expr_evaluator, '-validate-module',
                             '-llvmir2bir-converter=' + self.args.backend_llvmir2bir_converter, '-o', self.output,
                             self.out_backend_bc]

        if not self.args.backend_no_debug:
            llvmir2hll_params.append('-enable-debug')

        if not self.args.backend_no_debug_comments:
            llvmir2hll_params.append('-emit-debug-comments')

        if self.config:
            llvmir2hll_params.append('-config-path=' + self.config)

        if self.args.backend_semantics:
            llvmir2hll_params.extend(['-semantics', self.args.backend_semantics])

        if self.args.backend_enabled_opts:
            llvmir2hll_params.append('-enabled-opts=' + self.args.backend_enabled_opts)

        if self.args.backend_disabled_opts:
            llvmir2hll_params.append('-disabled-opts=' + self.args.backend_disabled_opts)

        if self.args.backend_no_opts:
            llvmir2hll_params.append('-no-opts')

        if self.args.backend_aggressive_opts:
            llvmir2hll_params.append('-aggressive-opts')

        if self.args.backend_no_var_renaming:
            llvmir2hll_params.append('-no-var-renaming')

        if self.args.backend_no_symbolic_names:
            llvmir2hll_params.append('-no-symbolic-names')

        if self.args.backend_keep_all_brackets:
            llvmir2hll_params.append('-keep-all-brackets')

        if self.args.backend_keep_library_funcs:
            llvmir2hll_params.append('-keep-library-funcs')

        if self.args.backend_no_time_varying_info:
            llvmir2hll_params.append('-no-time-varying-info')

        if self.args.backend_no_compound_operators:
            llvmir2hll_params.append('-no-compound-operators')

        if self.args.backend_find_patterns:
            llvmir2hll_params.extend(['-find-patterns', self.args.backend_find_patterns])

        if self.args.backend_emit_cg:
            llvmir2hll_params.append('-emit-cg')

        if self.args.backend_force_module_name:
            llvmir2hll_params.append('-force-module-name=' + self.args.backend_force_module_name)

        if self.args.backend_strict_fpu_semantics:
            llvmir2hll_params.append('-strict-fpu-semantics')

        if self.args.backend_emit_cfg:
            llvmir2hll_params.append('-emit-cfgs')

        if self.args.backend_cfg_test:
            llvmir2hll_params.append('--backend-cfg-test')

        if self.args.max_memory:
            llvmir2hll_params.extend(['-max-memory', self.args.max_memory])
        elif not self.args.no_memory_limit:
            # By default, we want to limit the memory of llvmir2hll into half of system
            # RAM to prevent potential black screens on Windows (#270).
            llvmir2hll_params.append('-max-memory-half-ram')

        # Decompile the optimized IR code.
        print()
        print('##### Decompiling ' + self.out_backend_bc + ' into ' + self.output + '...')
        print('RUN: ' + config.LLVMIR2HLL + ' ' + ' '.join(llvmir2hll_params))

        llvmir2hll_rc = 0

        if self.args.generate_log:
            """
            PID = 0

            def thread3():
                subprocess.call([TIME, config.LLVMIR2HLL] + llvmir2hll_params, shell=True, stdout=open(
                    tool_log_file, 'wb'), stderr=subprocess.STDOUT)

                threading.Thread(target=thread3).start()

                PID = 0  # TODO Expand.exclamation()

                def thread4():
                    self.timed_kill(PID)

            threading.Thread(target=self.thread4).start()

            os.kill(PID, 0)
            # subprocess.call(['wait', PID], shell=True, stderr=subprocess.STDOUT, stdout=subprocess.DEVNULL)

            llvmir2hll_rc = 0  # use rc _rc4
            LLVMIR2HLL_AND_TIME_OUTPUT = os.popen('cat \'' + tool_log_file + '\'').read().rstrip('\n')
            LOG_LLVMIR2HLL_RC = self.get_tool_rc(llvmir2hll_rc, LLVMIR2HLL_AND_TIME_OUTPUT)
            LOG_LLVMIR2HLL_RUNTIME = self.get_tool_runtime(LLVMIR2HLL_AND_TIME_OUTPUT)
            LOG_LLVMIR2HLL_MEMORY = self.get_tool_memory_usage(LLVMIR2HLL_AND_TIME_OUTPUT)
            LOG_LLVMIR2HLL_OUTPUT = self.get_tool_output(LLVMIR2HLL_AND_TIME_OUTPUT)

            print(LOG_LLVMIR2HLL_OUTPUT)
            # Wait a bit to ensure that all the memory that has been assigned to the tool was released.
            time.sleep(0.1)
            """
        else:
            llvmir2hll_out, llvmir2hll_rc, _ = cmd.run_cmd([config.LLVMIR2HLL, *llvmir2hll_params])
            print(llvmir2hll_out)

        if llvmir2hll_rc != 0:
            if self.args.generate_log:
                self.generate_log()

            self.cleanup()
            Utils.print_error('Decompilation of file %s failed' % self.out_backend_bc)
            return 1

        if self.check_whether_decompilation_should_be_forcefully_stopped('llvmir2hll'):
            return 0

        # Convert .dot graphs to desired format.
        if ((self.args.backend_emit_cg and self.args.backend_cg_conversion == 'auto') or (
                self.args.backend_emit_cfg and self.args.backend_cfg_conversion == 'auto')):
            print()
            print('##### Converting .dot files to the desired format...')

        if self.args.backend_emit_cg and self.args.backend_cg_conversion == 'auto':
            print(
                'RUN: dot -T' + self.args.graph_format + ' ' + self.output + '.cg.dot > ' + self.output + '.cg.' + self.args.graph_format)

            cmd.run_cmd(['dot', '-T' + self.args.graph_format, self.output + '.cg.dot'],
                        stdout=open(self.output + '.cg.' + self.args.graph_format, 'wb'))

        if self.args.backend_emit_cfg and self.args.backend_cfg_conversion == 'auto':
            for cfg in glob.glob(self.output + '.cfg.*.dot'):
                print('RUN: dot -T' + self.args.graph_format + ' ' + cfg + ' > ' + (
                        os.path.splitext(cfg)[0] + '.' + self.args.graph_format))

                cmd.run_cmd(['dot', '-T' + self.args.graph_format, cfg],
                            stdout=open((os.path.splitext(cfg)[0]) + '.' + self.args.graph_format, 'wb'))

        # Remove trailing whitespace and the last redundant empty new line from the
        # generated output (if any). It is difficult to do this in the back-end, so we
        # do it here.
        # Note: Do not use the -i flag (in-place replace) as there is apparently no way
        #       of getting sed -i to work consistently on both MacOS and Linux.
        # TODO
        with open(self.output, 'r') as file:
            new = [line.rstrip() for line in file]

        with open(self.output, 'w') as fh:
            [fh.write('%s\n' % line) for line in new]

        # Colorize output file.
        if self.args.color_for_ida:
            cmd.run_cmd([config.IDA_COLORIZER, self.output, self.config])

        # Store the information about the decompilation into the JSON file.
        if self.args.generate_log:
            self.generate_log()

        # Success!
        self.cleanup()
        print()
        print('##### Done!')

        return 0


if __name__ == '__main__':
    args = parse_args()

    decompiler = Decompiler(args)
    sys.exit(decompiler.decompile())

#!/usr/bin/env python3

"""Decompiles the given file into the selected target high-level language."""

import argparse
import glob
import os
import shutil
import sys
import time

import importlib
config = importlib.import_module('retdec-config')
retdec_signature_from_library_creator = importlib.import_module('retdec-signature-from-library-creator')
retdec_unpacker = importlib.import_module('retdec-unpacker')
utils = importlib.import_module('retdec-utils')

SigFromLib = retdec_signature_from_library_creator.SigFromLib
Unpacker = retdec_unpacker.Unpacker
CmdRunner = utils.CmdRunner


sys.stdout = utils.Unbuffered(sys.stdout)


def parse_args(args):
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
                        help='File with PDB debug information.')

    parser.add_argument('--generate-log',
                        dest='generate_log',
                        action='store_true',
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
                        action='store_true',
                        help='Enables aggressive optimizations.')

    parser.add_argument('--backend-arithm-expr-evaluator',
                        dest='backend_arithm_expr_evaluator',
                        default='c',
                        help='Name of the used evaluator of arithmetical expressions.')

    parser.add_argument('--backend-call-info-obtainer',
                        dest='backend_call_info_obtainer',
                        default='optim',
                        help='Name of the obtainer of information about function calls.')

    parser.add_argument('--backend-cfg-test',
                        dest='backend_cfg_test',
                        action='store_true',
                        help='Unifies the labels of all nodes in the emitted CFG (this has to be used in tests).')

    parser.add_argument('--backend-disabled-opts',
                        dest='backend_disabled_opts',
                        help='Prevents the optimizations from the given'
                             ' comma-separated list of optimizations to be run.')

    parser.add_argument('--backend-emit-cfg',
                        dest='backend_emit_cfg',
                        action='store_true',
                        help='Emits a CFG for each function in the backend IR (in the .dot format).')

    parser.add_argument('--backend-emit-cg',
                        dest='backend_emit_cg',
                        action='store_true',
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
                        action='store_true',
                        help='Keeps all brackets in the generated code.')

    parser.add_argument('--backend-keep-library-funcs',
                        dest='backend_keep_library_funcs',
                        action='store_true',
                        help='Keep functions from standard libraries.')

    parser.add_argument('--backend-llvmir2bir-converter',
                        dest='backend_llvmir2bir_converter',
                        default='orig',
                        choices=['orig', 'new'],
                        help='Name of the converter from LLVM IR to BIR.')

    parser.add_argument('--backend-no-compound-operators',
                        dest='backend_no_compound_operators',
                        action='store_true',
                        help='Do not emit compound operators (like +=) instead of assignments.')

    parser.add_argument('--backend-no-debug',
                        dest='backend_no_debug',
                        action='store_true',
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
                        action='append',
                        default=[],
                        help='Adds additional signature file for static code detection.')

    parser.add_argument('--static-code-archive',
                        dest='static_code_archive',
                        action='append',
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

    return parser.parse_args(args)


class Decompiler:
    def __init__(self, args):
        self.args = parse_args(args)

        self.input_file = ''
        self.output_file = ''
        self.config_file = ''
        self.selected_ranges = []
        self.selected_functions = []
        self.signatures_to_remove = []
        self.arch = ''
        self.mode = ''
        self.format = ''
        self.pdb_file = ''

        self.out_unpacked = ''
        self.out_frontend_ll = ''
        self.out_frontend_bc = ''
        self.out_backend_bc = ''
        self.out_backend_ll = ''
        self.out_restored = ''
        self.out_archive = ''

        self.log_decompilation_start_date = ''
        self.log_fileinfo_rc = 0
        self.log_fileinfo_time = 0
        self.log_fileinfo_output = ''
        self.log_fileinfo_memory = 0

        self.log_unpacker_output = ''
        self.log_unpacker_rc = 0

        self.log_bin2llvmir_rc = 0
        self.log_bin2llvmir_time = 0
        self.log_bin2llvmir_memory = 0
        self.log_bin2llvmir_output = ''

        self.log_llvmir2hll_rc = 0
        self.log_llvmir2hll_time = 0
        self.log_llvmir2hll_memory = 0
        self.log_llvmir2hll_output = ''

    def _check_arguments(self):
        """Check proper combination of input arguments.
        """

        # Check whether the input file was specified.
        if self.args.input:
            if not os.access(self.args.input, os.R_OK):
                utils.print_error('The input file \'%s\' does not exist or is not readable' % self.args.input)
                return False
            self.input_file = self.args.input
        else:
            utils.print_error('No input file was specified')
            return False

        if self.args.max_memory:
            if self.args.no_memory_limit:
                utils.print_error('Clashing options: --max-memory and --no-memory-limit')
                return False

            try:
                max_memory = int(self.args.max_memory)
                if max_memory <= 0:
                    utils.print_error('Invalid value for --max-memory: %s (expected a positive integer)'
                                      % self.args.max_memory)
                    return False
            except ValueError:
                utils.print_error('Invalid value for --max-memory: %s (expected a positive integer)'
                                  % self.args.max_memory)
                return False

        for sca in self.args.static_code_archive:
            if not os.path.isfile(sca):
                utils.print_error('Invalid archive file \'%s\'' % sca)
                return False

        for sigfile in self.args.static_code_sigfile:
            # User provided signature file.
            if not os.path.isfile(sigfile):
                utils.print_error('Invalid .yara file \'%s\'' % sigfile)
                return False

        if self.args.selected_ranges:
            self.selected_ranges = self.args.selected_ranges.strip().split(',')
            self.args.keep_unreachable_funcs = True

            # Check that selected ranges are valid.
            for r in self.selected_ranges:
                # Check if valid range.
                if not utils.is_range(r):
                    utils.print_error(
                        'Range %s in option --select-ranges is not a valid decimal (e.g. 123-456) or hexadecimal '
                        '(e.g. 0x123-0xabc) range.' % r)
                    return False

                # Check if first <= last.
                ranges = r.split('-')

                # parser line into array
                start_range = int(ranges[0], 16 if ranges[0].startswith('0x') else 10)
                end_range = int(ranges[1], 16 if ranges[1].startswith('0x') else 10)

                if start_range > end_range:
                    utils.print_error(
                        'Range \'%s\' in option --select-ranges is not a valid range: '
                        'second address must be greater or equal than the first one.' % ranges)
                    return False

        if self.args.selected_functions:
            self.selected_functions = self.args.selected_functions.strip().split(',')
            self.args.keep_unreachable_funcs = True

        if self.args.no_config:
            if self.args.config_db:
                utils.print_error('Option --no-config can not be used with option --config')
                return False

        if self.args.config_db:
            if not os.access(self.args.config_db, os.R_OK):
                utils.print_error('The input JSON configuration file \'%s\' does not exist or is not readable'
                                  % self.args.config_db)
                return False

        if self.args.pdb:
            # File containing PDB debug information.
            if not os.access(self.args.pdb, os.R_OK):
                utils.print_error('The input PDB file \'%s\' does not exist or is not readable' % self.args.pdb)
                return False

            self.pdb_file = os.path.abspath(self.args.pdb)

        # Try to detect desired decompilation mode if not set by user.
        # We cannot detect 'raw' mode because it overlaps with 'bin' (at least not based on extension).
        if not self.args.mode:
            if self.args.input.endswith('.ll'):
                self.mode = 'll'
            else:
                self.mode = 'bin'
        else:
            self.mode = self.args.mode

        # Print warning message about unsupported combinations of options.
        if self.mode == 'll':
            if self.args.arch:
                utils.print_warning('Option -a|--arch is not used in mode ' + self.mode)

            if self.args.pdb:
                utils.print_warning('Option -p|--pdb is not used in mode ' + self.mode)

            if not self.args.config_db and not self.args.no_config:
                utils.print_error('Option --config or --no-config must be specified in mode ' + self.mode)
                return False

        elif self.mode == 'raw':
            # Errors -- missing critical arguments.
            if not self.args.arch:
                utils.print_error('Option -a|--arch must be used with mode ' + self.mode)
                return False

            if not self.args.endian:
                utils.print_error('Option -e|--endian must be used with mode ' + self.mode)
                return False

            if not self.args.raw_entry_point:
                utils.print_error('Option --raw-entry-point must be used with mode ' + self.mode)
                return False

            if not self.args.raw_section_vma:
                utils.print_error('Option --raw-section-vma must be used with mode ' + self.mode)
                return False

            if not utils.is_number(self.args.raw_entry_point):
                utils.print_error(
                    'Value in option --raw-entry-point must be decimal (e.g. 123) or hexadecimal value (e.g. 0x123)')
                return False

            if not utils.is_number(self.args.raw_section_vma):
                utils.print_error(
                    'Value in option --raw-section-vma must be decimal (e.g. 123) or hexadecimal value (e.g. 0x123)')
                return False

        # Archive decompilation errors.
        if self.args.ar_name and self.args.ar_index:
            utils.print_error('Options --ar-name and --ar-index are mutually exclusive. Pick one.')
            return False

        if self.mode != 'bin':
            if self.args.ar_name:
                utils.print_warning('Option --ar-name is not used in mode ' + self.mode)

            if self.args.ar_index:
                utils.print_warning('Option --ar-index is not used in mode ' + self.mode)

        if not self.args.output:
            # No output file was given, so use the default one.
            input_name = self.input_file
            if input_name.endswith('.ll'):
                self.output_file = input_name[:-2] + self.args.hll
            elif input_name.endswith('.exe'):
                self.output_file = input_name[:-3] + self.args.hll
            elif input_name.endswith('.elf'):
                self.output_file = input_name[:-3] + self.args.hll
            elif input_name.endswith('.ihex'):
                self.output_file = input_name[:-4] + self.args.hll
            elif input_name.endswith('.macho'):
                self.output_file = input_name[:-5] + self.args.hll
            else:
                self.output_file = self.input_file + '.' + self.args.hll
        else:
            self.output_file = self.args.output

        # If the output file name matches the input file name, we have to change the
        # output file name. Otherwise, the input file gets overwritten.
        if self.input_file == self.output_file:
            self.output_file = self.input_file + '.out.' + self.args.hll

        # Convert to absolute paths.
        self.input_file = os.path.abspath(self.input_file)
        self.output_file = os.path.abspath(self.output_file)

        if self.args.arch:
            self.arch = self.args.arch

        return True

    def _print_warning_if_decompiling_bytecode(self):
        """Prints a warning if we are decompiling bytecode."""

        cmd = CmdRunner()
        bytecode, _, _ = cmd.run_cmd([config.CONFIGTOOL, self.config_file, '--read', '--bytecode'], buffer_output=True)

        if bytecode != '':
            utils.print_warning('Detected %s bytecode, which cannot be decompiled by our machine-code decompiler.'
                                ' The decompilation result may be inaccurate.' % bytecode)

    def _check_whether_decompilation_should_be_forcefully_stopped(self, tool_name):
        """Checks whether the decompilation should be forcefully stopped because of the
        --stop-after parameter. If so, cleanup is run and the script exits with 0.
        Arguments:
          tool_name Name of the tool.
        The function expects the self.args.stop_after variable to be set.
        """

        if self.args.stop_after == tool_name:
            if self.args.generate_log:
                self._generate_log()

            self._cleanup()
            print('\n#### Forced stop due to  \'--stop-after %s\'...' % self.args.stop_after)
            return True
        return False

    def _cleanup(self):
        """Cleanup working directory"""

        if self.args.cleanup:
            utils.remove_file_forced(self.out_unpacked)
            utils.remove_file_forced(self.out_frontend_ll)
            utils.remove_file_forced(self.out_frontend_bc)

            if self.config_file != self.args.config_db:
                utils.remove_file_forced(self.config_file)

            utils.remove_file_forced(self.out_backend_bc)
            utils.remove_file_forced(self.out_backend_ll)

            # Archive support
            utils.remove_file_forced(self.out_restored)
            # Archive support (Macho-O Universal)
            utils.remove_file_forced(self.out_archive)

            # Signatures generated from archives
            for sig in self.signatures_to_remove:
                utils.remove_file_forced(sig)

    def _generate_log(self):
        log_file = self.output_file + '.decompilation.log'
        log_decompilation_end_date = str(int(time.time()))

        self.log_fileinfo_output = self._json_escape(self.log_fileinfo_output)
        self.log_unpacker_output = self._json_escape(self.log_unpacker_output)
        self.log_bin2llvmir_output = self._json_escape(self.log_bin2llvmir_output)
        self.log_llvmir2hll_output = self._json_escape(self.log_llvmir2hll_output)

        log_structure = '{\n\t\"input_file\" : \"%s\",\n\t\"pdb_file\" : \"%s\",\n\t\"start_date\" : \"%s\",\n\t\"' \
                        'end_date\" : \"%s\",\n\t\"mode\" : \"%s\",\n\t\"arch\" : \"%s\",\n\t\"format\" : \"%s\",\n\t\"' \
                        'fileinfo_rc\" : \"%s\",\n\t\"unpacker_rc\" : \"%s\",\n\t\"bin2llvmir_rc\" : \"%s\",\n\t\"' \
                        'llvmir2hll_rc\" : \"%s\",\n\t\"fileinfo_output\" : \"%s\",\n\t\"unpacker_output\" : \"%s\",' \
                        '\n\t\"bin2llvmir_output\" : \"%s\",\n\t\"llvmir2hll_output\" : \"%s\",\n\t\"fileinfo_runtime\"' \
                        ' : \"%s\",\n\t\"bin2llvmir_runtime\" : \"%s\",\n\t\"llvmir2hll_runtime\" : \"%s\",\n\t\"' \
                        'fileinfo_memory\" : \"%s\",\n\t\"bin2llvmir_memory\" : \"%s\",\n\t\"llvmir2hll_memory\"' \
                        ' : \"%s\"\n}\n'

        json_string = log_structure % (
            self.input_file, self.pdb_file, self.log_decompilation_start_date, log_decompilation_end_date, self.mode,
            self.arch, self.format, self.log_fileinfo_rc, self.log_unpacker_rc, self.log_bin2llvmir_rc,
            self.log_llvmir2hll_rc, self.log_fileinfo_output, self.log_unpacker_output, self.log_bin2llvmir_output,
            self.log_llvmir2hll_output, self.log_fileinfo_time, self.log_bin2llvmir_time, self.log_llvmir2hll_time,
            self.log_fileinfo_memory, self.log_bin2llvmir_memory, self.log_llvmir2hll_memory)

        with open(log_file, 'w+') as f:
            f.write(json_string)

    def _json_escape(self, string):
        return string.rstrip('\r\n').replace('\n', r'\n') if string else None

    def decompile(self):
        cmd = CmdRunner()

        # Check arguments and set default values for unset options.
        if not self._check_arguments():
            return 1

        # Initialize variables used by logging.
        if self.args.generate_log:
            self.log_decompilation_start_date = str(int(time.time()))

        if self.args.raw_entry_point:
            self.args.raw_entry_point = int(self.args.raw_entry_point, 16 if self.args.raw_entry_point.startswith('0x') else 10)

        # Raw.
        if self.mode == 'raw':
            # Entry point for THUMB must be odd.
            if self.args.arch == 'thumb' and (self.args.raw_entry_point % 2) == 0:
                self.args.raw_entry_point = (self.args.raw_entry_point + 1)

            self.args.keep_unreachable_funcs = True

        # Check for archives.
        if self.mode == 'bin':
            # Check for archives packed in Mach-O Universal Binaries.
            print('##### Checking if file is a Mach-O Universal static library...')

            if utils.is_macho_archive(self.input_file):
                out_archive = self.output_file + '.a'
                if self.args.arch:
                    print('\n##### Restoring static library with architecture family ' + self.args.arch + '...')
                    _, extract_rc, _ = cmd.run_cmd(
                        [config.EXTRACT, '--family', self.args.arch, '--out', out_archive, self.input_file], print_run_msg=True)
                    if extract_rc:
                        # Architecture not supported
                        print('Invalid --arch option \'' + self.args.arch +
                              '\'. File contains these architecture families:')
                        cmd.run_cmd([config.EXTRACT, '--list', self.input_file])
                        self._cleanup()
                        return 1
                else:
                    # Pick best architecture
                    print('\n##### Restoring best static library for decompilation...')
                    cmd.run_cmd([config.EXTRACT, '--best', '--out', out_archive, self.input_file], print_run_msg=True)

                self.input_file = out_archive

            print('\n##### Checking if file is an archive...')
            if utils.has_archive_signature(self.input_file, print_run_msg=True):
                print('This file is an archive!')

                # Check for thin signature.
                if utils.has_thin_archive_signature(self.input_file):
                    self._cleanup()
                    utils.print_error('File is a thin archive and cannot be decompiled.')
                    return 1

                # Check if our tools can handle it.
                if not utils.is_valid_archive(self.input_file):
                    self._cleanup()
                    utils.print_error('The input archive has invalid format.')
                    return 1

                # Get and check number of objects.
                arch_object_count = utils.archive_object_count(self.input_file)
                if arch_object_count <= 0:
                    self._cleanup()
                    utils.print_error('The input archive is empty.')
                    return 1

                # Prepare object output path.
                out_restored = self.output_file + '.restored'

                # Pick object by index.
                if self.args.ar_index:
                    print('\n##### Restoring object file on index \'%s\' from archive...' % self.args.ar_index)
                    if utils.archive_get_by_index(self.input_file, self.args.ar_index, out_restored, print_run_msg=True):
                        self._cleanup()
                        valid_index = (arch_object_count - 1)

                        if valid_index != 0:
                            utils.print_error('File on index \'' + self.args.ar_index
                                              + '\' was not found in the input archive. Valid indexes are 0-' + (
                                                  str(valid_index)) + '.')
                            return 1
                        else:
                            utils.print_error('File on index \'' + self.args.ar_index +
                                              '\' was not found in the input archive. The only valid index is 0.')
                            return 1

                    self.input_file = out_restored
                # Pick object by name
                elif self.args.ar_name:
                    print('\n##### Restoring object file with name \'%s\' from archive...' % self.args.ar_name)
                    if utils.archive_get_by_name(self.input_file, self.args.ar_name, out_restored, print_run_msg=True):
                        self._cleanup()
                        utils.print_error('File named \'%s\' was not found in the input archive.' % self.args.ar_name)
                        return 1

                    self.input_file = out_restored
                else:
                    # Print list of files.
                    print('Please select file to decompile with either \' --ar-index=n\'')
                    print('or \' --ar-name=string\' option. Archive contains these files:')

                    utils.archive_list_numbered_content(self.input_file)
                    self._cleanup()
                    return 1
            else:
                if self.args.ar_name:
                    utils.print_warning('Option --ar-name can be used only with archives.')

                if self.args.ar_index:
                    utils.print_warning('Option --ar-index can be used only with archives.')

                print('Not an archive, going to the next step.')

        if self.mode in ['bin', 'raw']:
            # Assignment of other used variables.
            name = os.path.splitext(self.output_file)[0]
            out_frontend = self.output_file + '.frontend'
            self.out_unpacked = name + '-unpacked'
            self.out_frontend_ll = out_frontend + '.ll'
            self.out_frontend_bc = out_frontend + '.bc'
            self.config_file = self.output_file + '.json'

            if self.config_file != self.args.config_db:
                utils.remove_file_forced(self.config_file)

            if self.args.config_db:
                shutil.copyfile(self.args.config_db, self.config_file)

            # Preprocess existing file or create a new, empty JSON file.
            if os.path.isfile(self.config_file):
                cmd.run_cmd([config.CONFIGTOOL, self.config_file, '--preprocess'])
            else:
                with open(self.config_file, 'w') as f:
                    f.write('{}')

            # Raw data needs architecture, endianess and optionally sections's vma and entry point to be specified.
            if self.mode == 'raw':
                if not self.arch or self.arch == 'unknown' or self.arch == '':
                    utils.print_error('Option -a|--arch must be used with mode ' + self.mode)
                    return 1

                if not self.args.endian:
                    utils.print_error('Option -e|--endian must be used with mode ' + self.mode)
                    return 1

                cmd.run_cmd([config.CONFIGTOOL, self.config_file, '--write', '--format', 'raw'])
                cmd.run_cmd([config.CONFIGTOOL, self.config_file, '--write', '--arch', self.arch])
                cmd.run_cmd([config.CONFIGTOOL, self.config_file, '--write', '--bit-size', '32'])
                cmd.run_cmd([config.CONFIGTOOL, self.config_file, '--write', '--file-class', '32'])
                cmd.run_cmd([config.CONFIGTOOL, self.config_file, '--write', '--endian', self.args.endian])

                if self.args.raw_entry_point:
                    cmd.run_cmd([config.CONFIGTOOL, self.config_file, '--write', '--entry-point',
                                 hex(self.args.raw_entry_point)])

                if self.args.raw_section_vma:
                    cmd.run_cmd([config.CONFIGTOOL, self.config_file, '--write', '--section-vma',
                                 self.args.raw_section_vma])

            #
            # Call fileinfo to create an initial config file.
            #
            fileinfo_params = ['-c', self.config_file, '--similarity', self.input_file, '--no-hashes=all']

            if self.args.fileinfo_verbose:
                fileinfo_params = ['-c', self.config_file, '--similarity', '--verbose', self.input_file]

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

            print('\n##### Gathering file information...')
            fileinfo_rc = 0
            if self.args.generate_log:
                self.log_fileinfo_memory, self.log_fileinfo_time, self.log_fileinfo_output, self.log_fileinfo_rc = \
                    cmd.run_measured_cmd([config.FILEINFO] + fileinfo_params, timeout=config.LOG_TIMEOUT, print_run_msg=True)

                print(self.log_fileinfo_output)
            else:
                _, fileinfo_rc, _ = cmd.run_cmd([config.FILEINFO] + fileinfo_params, print_run_msg=True)

            if fileinfo_rc != 0:
                if self.args.generate_log:
                    self._generate_log()

                self._cleanup()
                return 1

            if self._check_whether_decompilation_should_be_forcefully_stopped('fileinfo'):
                return 0

            #
            # Unpacking.
            #
            unpack_params = ['--extended-exit-codes', '--output', self.out_unpacked, self.input_file]

            if self.args.max_memory:
                unpack_params.extend(['--max-memory', self.args.max_memory])
            elif not self.args.no_memory_limit:
                # By default, we want to limit the memory of retdec-unpacker into half
                # of system RAM to prevent potential black screens on Windows (#270).
                unpack_params.append('--max-memory-half-ram')

            unpacker = Unpacker(unpack_params)
            if self.args.generate_log:
                # we should get the output from the unpacker tool
                self.log_unpacker_output, self.log_unpacker_rc = unpacker.unpack_all(log_output=True)

                unpacker_rc = self.log_unpacker_rc
                print(self.log_unpacker_output)
            else:
                _, unpacker_rc = unpacker.unpack_all()

            if self._check_whether_decompilation_should_be_forcefully_stopped('unpacker'):
                return 0

            # RET_UNPACK_OK=0
            # RET_UNPACKER_NOTHING_TO_DO_OTHERS_OK=1
            # RET_UNPACKER_FAILED_OTHERS_OK=3
            if unpacker_rc == Unpacker.RET_UNPACK_OK or unpacker_rc == Unpacker.RET_UNPACKER_NOTHING_TO_DO_OTHERS_OK \
                    or unpacker_rc == Unpacker.RET_UNPACKER_FAILED_OTHERS_OK:

                # Successfully unpacked -> re-run fileinfo to obtain fresh information.
                self.input_file = self.out_unpacked
                fileinfo_params = ['-c', self.config_file, '--similarity', self.input_file, '--no-hashes=all']

                if self.args.fileinfo_verbose:
                    fileinfo_params = ['-c', self.config_file, '--similarity', '--verbose', self.input_file]

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

                print('\t##### Gathering file information after unpacking...')
                if self.args.generate_log:
                    fileinfo_memory, fileinfo_time, self.log_fileinfo_output, self.log_fileinfo_rc \
                        = cmd.run_measured_cmd([config.FILEINFO] + fileinfo_params, timeout=config.LOG_TIMEOUT, print_run_msg=True)

                    fileinfo_rc = self.log_fileinfo_rc
                    self.log_fileinfo_time += fileinfo_time
                    self.log_fileinfo_memory = (self.log_fileinfo_memory + fileinfo_memory) / 2

                    print(self.log_fileinfo_output)
                else:
                    _, fileinfo_rc, _ = cmd.run_cmd([config.FILEINFO] + fileinfo_params, print_run_msg=True)

                if fileinfo_rc != 0:
                    if self.args.generate_log:
                        self._generate_log()

                    self._cleanup()
                    return 1

                self._print_warning_if_decompiling_bytecode()

            # Check whether the architecture was specified.
            if self.arch:
                cmd.run_cmd([config.CONFIGTOOL, self.config_file, '--write', '--arch', self.arch])
            else:
                # Get full name of the target architecture including comments in parentheses
                arch_full, _, _ = cmd.run_cmd([config.CONFIGTOOL, self.config_file, '--read', '--arch'], buffer_output=True)
                arch_full = arch_full.lower()

                # Strip comments in parentheses and all trailing whitespace
                self.arch = arch_full.split(' ')[0]

            # Get object file format.
            self.format, _, _ = cmd.run_cmd([config.CONFIGTOOL, self.config_file, '--read', '--format'], buffer_output=True)
            self.format = self.format.lower()

            # Intel HEX needs architecture to be specified
            if self.format in ['ihex']:
                if not self.arch or self.arch == 'unknown':
                    utils.print_error('Option -a|--arch must be used with format ' + self.format)
                    return 1

                if not self.args.endian:
                    utils.print_error('Option -e|--endian must be used with format ' + self.format)
                    return 1

                cmd.run_cmd([config.CONFIGTOOL, self.config_file, '--write', '--arch', self.arch])
                cmd.run_cmd([config.CONFIGTOOL, self.config_file, '--write', '--bit-size', '32'])
                cmd.run_cmd([config.CONFIGTOOL, self.config_file, '--write', '--file-class', '32'])
                cmd.run_cmd([config.CONFIGTOOL, self.config_file, '--write', '--endian', self.args.endian])

            ords_dir = ''
            # Check whether the correct target architecture was specified.
            if self.arch in ['arm', 'thumb']:
                ords_dir = config.ARM_ORDS_DIR
            elif self.arch in ['x86']:
                ords_dir = config.X86_ORDS_DIR
            elif self.arch in ['powerpc', 'mips', 'pic32']:
                pass
            else:
                if self.args.generate_log:
                    self._generate_log()

                self._cleanup()
                utils.print_error('Unsupported target architecture \'%s\'. Supported architectures: '
                                  'Intel x86, ARM, ARM + Thumb, MIPS, PIC32, PowerPC.' % self.arch)
                return 1

            # Check file class (e.g. 'ELF32', 'ELF64'). At present, we can only decompile 32-bit files.
            # Note: we prefer to report the 'unsupported architecture' error (above) than this 'generic' error.
            fileclass, _, _ = cmd.run_cmd([config.CONFIGTOOL, self.config_file, '--read', '--file-class'], buffer_output=True)

            if fileclass not in ['16', '32']:
                if self.args.generate_log:
                    self._generate_log()

                self._cleanup()
                utils.print_error(
                    'Unsupported target format \'%s%s\'. Supported formats: ELF32, PE32, Intel HEX 32, Mach-O 32.' % (
                        self.format.upper(), fileclass))
                return 1

            # Set path to statically linked code signatures.
            #
            # TODO: Using ELF for IHEX is ok, but for raw, we probably should somehow decide between ELF and PE,
            # or use both, for RAW.
            sig_format = self.format

            if sig_format in ['ihex', 'raw']:
                sig_format = 'elf'

            endian_result, _, _ = cmd.run_cmd([config.CONFIGTOOL, self.config_file, '--read', '--endian'], buffer_output=True)

            if endian_result == 'little':
                sig_endian = 'le'
            elif endian_result == 'big':
                sig_endian = 'be'
            else:
                if self.args.generate_log:
                    self._generate_log()

                self._cleanup()
                utils.print_error('Cannot determine endiannesss.')
                return 1

            sig_arch = self.arch

            if sig_arch == 'pic32':
                sig_arch = 'mips'

            signatures_dir = os.path.join(config.GENERIC_SIGNATURES_DIR, sig_format, fileclass, sig_endian, sig_arch)

            self._print_warning_if_decompiling_bytecode()

            # Decompile unreachable functions.
            if self.args.keep_unreachable_funcs:
                cmd.run_cmd([config.CONFIGTOOL, self.config_file, '--write', '--keep-unreachable-funcs', 'true'])

            if self.args.static_code_archive:
                # Get signatures from selected archives.
                if len(self.args.static_code_archive) > 0:
                    print('\n##### Extracting signatures from selected archives...')

                lib_index = 0
                for lib in self.args.static_code_archive:

                    print('Extracting signatures from file \'%s\'' % lib)
                    crop_arch_path = os.path.basename(lib)
                    sig_out = self.output_file + '.' + crop_arch_path + '.' + str(lib_index) + '.yara'

                    # Call sig from lib tool
                    sig_from_lib = SigFromLib([lib, '--output', sig_out])
                    if not sig_from_lib.run():
                        cmd.run_cmd([config.CONFIGTOOL, self.config_file, '--write', '--user-signature', sig_out])
                        self.signatures_to_remove.append(sig_out)
                    else:
                        utils.print_warning('Failed extracting signatures from file \'' + lib + '\'')

                    lib_index += 1

            # Store paths of signature files into config for frontend.
            if not self.args.no_default_static_signatures:
                cmd.run_cmd([config.CONFIGTOOL, self.config_file, '--write', '--signatures', signatures_dir])

            # User provided signatures.
            for i in self.args.static_code_sigfile:
                cmd.run_cmd([config.CONFIGTOOL, self.config_file, '--write', '--user-signature', i])

            # Store paths of type files into config for frontend.
            if os.path.isdir(config.GENERIC_TYPES_DIR):
                cmd.run_cmd([config.CONFIGTOOL, self.config_file, '--write', '--types', config.GENERIC_TYPES_DIR])

            # Store path of directory with ORD files into config for frontend (note: only directory,
            # not files themselves).
            if os.path.isdir(ords_dir):
                cmd.run_cmd([config.CONFIGTOOL, self.config_file, '--write', '--ords', ords_dir + os.path.sep])

            # Store paths to file with PDB debugging information into config for frontend.
            if self.pdb_file:
                cmd.run_cmd([config.CONFIGTOOL, self.config_file, '--write', '--pdb-file', self.pdb_file])

            # Store file names of input and output into config for frontend.
            cmd.run_cmd([config.CONFIGTOOL, self.config_file, '--write', '--input-file', self.input_file])
            cmd.run_cmd([config.CONFIGTOOL, self.config_file, '--write', '--frontend-output-file',
                         self.out_frontend_ll])
            cmd.run_cmd([config.CONFIGTOOL, self.config_file, '--write', '--output-file', self.output_file])

            # Store decode only selected parts flag.
            if self.args.selected_decode_only:
                cmd.run_cmd([config.CONFIGTOOL, self.config_file, '--write', '--decode-only-selected', 'true'])
            else:
                cmd.run_cmd([config.CONFIGTOOL, self.config_file, '--write', '--decode-only-selected', 'false'])

            # Store selected functions or selected ranges into config for frontend.
            if self.selected_functions:
                for f in self.selected_functions:
                    cmd.run_cmd([config.CONFIGTOOL, self.config_file, '--write', '--selected-func', f])

            if self.selected_ranges:
                for r in self.selected_ranges:
                    cmd.run_cmd([config.CONFIGTOOL, self.config_file, '--write', '--selected-range', r])

            # Assignment of other used variables.
            # We have to ensure that the .bc version of the decompiled .ll file is placed
            # in the same directory as are other output files. Otherwise, there may be
            # race-condition problems when the same input .ll file is decompiled in
            # parallel processes because they would overwrite each other's .bc file. This
            # is most likely to happen in regression tests in the 'll' mode.
            out_backend = self.output_file + '.backend'

            # If the input file is the same as out_backend_ll below, then we have to change the name of
            # out_backend. Otherwise, the input file would get overwritten during the conversion.
            if self.out_frontend_ll == out_backend + '.ll':
                out_backend = self.output_file + '.backend.backend'

            self.out_backend_bc = out_backend + '.bc'
            self.out_backend_ll = out_backend + '.ll'

            #
            # Decompile the binary into LLVM IR.
            #
            bin2llvmir_params = config.BIN2LLVMIR_PARAMS

            if self.args.keep_unreachable_funcs:
                # Prevent bin2llvmir from removing unreachable functions.
                bin2llvmir_params.remove('-unreachable-funcs')

            if self.config_file == '' or not self.config_file and self.args.config_db:
                self.config_file = self.args.config_db

            bin2llvmir_params.extend(['-config-path', self.config_file])

            if self.args.max_memory:
                bin2llvmir_params.extend(['-max-memory', self.args.max_memory])
            elif not self.args.no_memory_limit:
                # By default, we want to limit the memory of bin2llvmir into half of
                # system RAM to prevent potential black screens on Windows (#270).
                bin2llvmir_params.append('-max-memory-half-ram')

            print('\n##### Decompiling ' + self.input_file + ' into ' + self.out_backend_bc + '...')
            if self.args.generate_log:
                self.log_bin2llvmir_memory, self.log_bin2llvmir_time, self.log_bin2llvmir_output, \
                self.log_bin2llvmir_rc = cmd.run_measured_cmd([config.BIN2LLVMIR] + bin2llvmir_params + ['-o',
                                                               self.out_backend_bc], timeout=config.LOG_TIMEOUT, print_run_msg=True)

                bin2llvmir_rc = self.log_bin2llvmir_rc
                print(self.log_bin2llvmir_output)
            else:
                _, bin2llvmir_rc, _ = cmd.run_cmd([config.BIN2LLVMIR] + bin2llvmir_params + ['-o', self.out_backend_bc], print_run_msg=True)

            if bin2llvmir_rc != 0:
                if self.args.generate_log:
                    self._generate_log()

                self._cleanup()
                utils.print_error('Decompilation to LLVM IR failed')
                return 1

            if self._check_whether_decompilation_should_be_forcefully_stopped('bin2llvmir'):
                return 0

        # LL mode goes straight to backend.
        if self.mode == 'll':
            self.out_backend_bc = self.input_file
            self.config_file = self.args.config_db

        # Create parameters for the llvmir2hll call.
        llvmir2hll_params = ['-target-hll=' + self.args.hll, '-var-renamer=' + self.args.backend_var_renamer,
                             '-var-name-gen=fruit', '-var-name-gen-prefix=',
                             '-call-info-obtainer=' + self.args.backend_call_info_obtainer,
                             '-arithm-expr-evaluator=' + self.args.backend_arithm_expr_evaluator, '-validate-module',
                             '-llvmir2bir-converter=' + self.args.backend_llvmir2bir_converter, '-o', self.output_file,
                             self.out_backend_bc]

        if not self.args.backend_no_debug:
            llvmir2hll_params.append('-enable-debug')

        if not self.args.backend_no_debug_comments:
            llvmir2hll_params.append('-emit-debug-comments')

        if self.config_file:
            llvmir2hll_params.append('-config-path=' + self.config_file)

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
        print('\n##### Decompiling ' + self.out_backend_bc + ' into ' + self.output_file + '...')
        if self.args.generate_log:
            self.log_llvmir2hll_memory, self.log_llvmir2hll_time, self.log_llvmir2hll_output, \
            self.log_llvmir2hll_rc = cmd.run_measured_cmd([config.LLVMIR2HLL] + llvmir2hll_params, timeout=config.LOG_TIMEOUT, print_run_msg=True)

            llvmir2hll_rc = self.log_llvmir2hll_rc
            print(self.log_llvmir2hll_output)
        else:
            _, llvmir2hll_rc, _ = cmd.run_cmd([config.LLVMIR2HLL] + llvmir2hll_params, print_run_msg=True)

        if llvmir2hll_rc != 0:
            if self.args.generate_log:
                self._generate_log()

            self._cleanup()
            utils.print_error('Decompilation of file %s failed' % self.out_backend_bc)
            return 1

        if self._check_whether_decompilation_should_be_forcefully_stopped('llvmir2hll'):
            return 0

        # Convert .dot graphs to desired format.
        if ((self.args.backend_emit_cg and self.args.backend_cg_conversion == 'auto') or (
                self.args.backend_emit_cfg and self.args.backend_cfg_conversion == 'auto')):
            print('\n##### Converting .dot files to the desired format...')

        if self.args.backend_emit_cg and self.args.backend_cg_conversion == 'auto':
            if utils.tool_exists('dot'):
                cmd.run_cmd(['dot', '-T' + self.args.graph_format, self.output_file + '.cg.dot', '-o',
                             self.output_file + '.cg.' + self.args.graph_format], print_run_msg=True)
            else:
                print('Please install \'Graphviz\' to generate graphics.')

        if self.args.backend_emit_cfg and self.args.backend_cfg_conversion == 'auto':
            if utils.tool_exists('dot'):
                for cfg in glob.glob(self.output_file + '.cfg.*.dot'):
                    cmd.run_cmd(['dot', '-T' + self.args.graph_format, cfg, '-o',
                                 os.path.splitext(cfg)[0] + '.' + self.args.graph_format], print_run_msg=True)
            else:
                print('Please install \'Graphviz\' to generate graphics.')

        # Remove trailing whitespace and the last redundant empty new line from the
        # generated output (if any). It is difficult to do this in the back-end, so we
        # do it here.
        with open(self.output_file, 'r') as file:
            new = [line.rstrip() for line in file]
            if new and new[-1] == '':
                new.pop()

        with open(self.output_file, 'w') as fh:
            [fh.write('%s\n' % line) for line in new]

        # Colorize output file.
        if self.args.color_for_ida:
            cmd.run_cmd([sys.executable, config.IDA_COLORIZER, self.output_file, self.config_file])

        # Store the information about the decompilation into the JSON file.
        if self.args.generate_log:
            self._generate_log()

        # Success!
        self._cleanup()
        print('\n##### Done!')

        return 0


if __name__ == '__main__':
    decompiler = Decompiler(sys.argv[1:])
    sys.exit(decompiler.decompile())

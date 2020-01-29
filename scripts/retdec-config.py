#!/usr/bin/env python3

import os
from sys import platform

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

"""Paths (everything has to be without the ending slash '/').

Paths relative from script path.
"""
INSTALL_BIN_DIR = SCRIPT_DIR
UNIT_TESTS_DIR = INSTALL_BIN_DIR
INSTALL_SHARE_DIR = os.path.join(INSTALL_BIN_DIR, '..', 'share', 'retdec')
INSTALL_SUPPORT_DIR = os.path.join(INSTALL_SHARE_DIR, 'support')
INSTALL_SHARE_YARA_DIR = os.path.join(INSTALL_SUPPORT_DIR, 'generic', 'yara_patterns')

# generic configuration
GENERIC_TYPES_DIR = os.path.join(INSTALL_SUPPORT_DIR, 'generic', 'types')
GENERIC_SIGNATURES_DIR = os.path.join(INSTALL_SHARE_YARA_DIR, 'static-code')

# ARM-specific configuration
ARM_ORDS_DIR = os.path.join(INSTALL_SUPPORT_DIR, 'arm', 'ords')
# X86-specific configuration
X86_ORDS_DIR = os.path.join(INSTALL_SUPPORT_DIR, 'x86', 'ords')

# TODO: disable-inlining

"""BIN2LLVMIR parameters

The following options are useful during debugging of bin2llvmirl optimizations.
parameters beginning with -disable-* may be included only once, which is the
 * -print-after-all -debug-only=idioms -print-before=idioms -print-after=idioms

 -unreachable-funcs is automatically removed in decompilation script when the
 -k/--keep-unreachable-funcs parameter is used.

 - We need to run -instcombine after -dead-global-assign to eliminate dead
 instructions after this optimization.

 - Optimization -phi2seq is needed to be run at the end and not to run two
 times. This is the reason why it is placed at the very end.
"""
BIN2LLVMIR_LLVM_PASSES_ONLY = [
    '-instcombine',
    '-tbaa',
    '-basicaa',
    '-simplifycfg',
    '-early-cse',
    '-tbaa',
    '-basicaa',
    '-globalopt',
    '-mem2reg',
    '-instcombine',
    '-simplifycfg',
    '-early-cse',
    '-lazy-value-info',
    '-jump-threading',
    '-correlated-propagation',
    '-simplifycfg',
    '-instcombine',
    '-simplifycfg',
    '-reassociate',
    '-loops',
    '-loop-simplify',
    '-lcssa',
    '-loop-rotate',
    '-licm',
    '-lcssa',
    '-instcombine',
    '-loop-simplifycfg',
    '-loop-simplify',
    '-aa',
    '-loop-accesses',
    '-loop-load-elim',
    '-lcssa',
    '-indvars',
    '-loop-idiom',
    '-loop-deletion',
    '-gvn',
    '-sccp',
    '-instcombine',
    '-lazy-value-info',
    '-jump-threading',
    '-correlated-propagation',
    '-dse',
    '-bdce',
    '-adce',
    '-simplifycfg',
    '-instcombine',
    '-strip-dead-prototypes',
    '-globaldce',
    '-constmerge',
    '-constprop',
    '-instcombine',
]

BIN2LLVMIR_PARAMS = [
    '-provider-init',
    '-decoder',
    '-verify',
    '-x87-fpu',
    '-main-detection',
    '-idioms-libgcc',
    '-inst-opt',
    '-cond-branch-opt',
    '-syscalls',
    '-stack',
    '-constants',
    '-param-return',
    '-local-vars',
    '-inst-opt',
    '-simple-types',
    '-generate-dsm',
    '-remove-asm-instrs',
    '-class-hierarchy',
    '-select-fncs',
    '-unreachable-funcs',
    '-inst-opt',
    '-x86-addr-spaces',
    '-register-localization',
    '-value-protect',
] + BIN2LLVMIR_LLVM_PASSES_ONLY + BIN2LLVMIR_LLVM_PASSES_ONLY + [
    '-inst-opt',
    '-simple-types',
    '-stack-ptr-op-remove',
    '-idioms',
    '-instcombine',
    '-inst-opt',
    '-idioms',
    '-remove-phi',
    '-value-protect',
    '-sink'
]

# Paths to tools.
FILEINFO = os.path.join(INSTALL_BIN_DIR, 'retdec-fileinfo')

FILEINFO_EXTERNAL_YARA_PRIMARY_CRYPTO_DATABASES = [
    os.path.join(INSTALL_SHARE_YARA_DIR, 'signsrch', 'signsrch.yara'),
    os.path.join(INSTALL_SHARE_YARA_DIR, 'signsrch', 'signsrch.yarac')]
FILEINFO_EXTERNAL_YARA_EXTRA_CRYPTO_DATABASES = [
    os.path.join(INSTALL_SHARE_YARA_DIR, 'signsrch', 'signsrch_regex.yara'),
    os.path.join(INSTALL_SHARE_YARA_DIR, 'signsrch', 'signsrch_regex.yarac')]

AR = os.path.join(INSTALL_BIN_DIR, 'retdec-ar-extractor')
BIN2PAT = os.path.join(INSTALL_BIN_DIR, 'retdec-bin2pat')
PAT2YARA = os.path.join(INSTALL_BIN_DIR, 'retdec-pat2yara')
CONFIGTOOL = os.path.join(INSTALL_BIN_DIR, 'retdec-config')
EXTRACT = os.path.join(INSTALL_BIN_DIR, 'retdec-macho-extractor')
DECOMPILER = os.path.join(INSTALL_BIN_DIR, 'retdec_decompiler.py')
ARCHIVE_DECOMPILER = os.path.join(INSTALL_BIN_DIR, 'retdec_archive_decompiler.py')
SIG_FROM_LIB = os.path.join(INSTALL_BIN_DIR, 'retdec_signature_from_library_creator.py')
UNPACK = os.path.join(INSTALL_BIN_DIR, 'retdec_unpacker.py')
LLVMIR2HLL = os.path.join(INSTALL_BIN_DIR, 'retdec-llvmir2hll')
BIN2LLVMIR = os.path.join(INSTALL_BIN_DIR, 'retdec-bin2llvmir')
UNPACKER = os.path.join(INSTALL_BIN_DIR, 'retdec-unpacker')

# Other.

if platform == "darwin":
    # mac os x need the `gnu-time´ package
    LOG_TIME = ['/usr/local/bin/gtime', '-v']
else:
    LOG_TIME = ['/usr/bin/time', '-v']
LOG_TIMEOUT = 300

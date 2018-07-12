#!/usr/bin/env python3

"""Compile and install tool signatures.
Usage: compile-yara.py yarac-path source-path install-path
"""

import os
import shutil
import subprocess
import sys


###############################################################################

def print_error_and_die(error):
    """Print error and exit with non-zero value.
         error - error message.
    """
    print('Error: %s.' % error)
    sys.exit(1)


def compile_files(input_folder, output_folder):
    """Compile yara signatures.
        input_folder - input folder
        output_folder - output file
    """

    p = subprocess.Popen([yarac, '-w', input_folder + '/*.yara', output_folder])
    out, _ = p.communicate()

    if p.returncode != 0:
        print_error_and_die('yarac failed during compilation of file' + input_folder)

    # Check for errors in output - yarac returns 0 when it should not.
    if 'error' in out:
        print_error_and_die('yarac failed during compilation of file ' + input_folder)


###############################################################################

if len(sys.argv) < 2:
    print_error_and_die('missing path to yarac')
yarac = sys.argv[1]

if len(sys.argv) < 3:
    print_error_and_die('missing path to rules folder')

rules_dir = sys.argv[2]

if len(sys.argv) < 4:
    print_error_and_die('missing path to install folder')

install_dir = sys.argv[3]

###############################################################################

# Directory paths.
rules_dir = os.path.join(rules_dir, 'support', 'yara_patterns', 'tools')
install_dir = os.path.join(install_dir, 'share', 'retdec', 'support', 'generic', 'yara_patterns', 'tools')

###############################################################################

# Remove old files if present.
if os.path.isfile(install_dir) or os.path.islink(install_dir):
    os.unlink(install_dir)
else:
    shutil.rmtree(install_dir, ignore_errors=True)

# Prepare directory structure.
os.makedirs(os.path.join(install_dir, 'pe'), exist_ok=True)
os.makedirs(os.path.join(install_dir, 'elf'), exist_ok=True)
os.makedirs(os.path.join(install_dir, 'macho'), exist_ok=True)

###############################################################################

print('compiling yara signatures...')

# Compile PE32 signatures.
compile_files(os.path.join(rules_dir, 'pe', 'x86'), os.path.join(install_dir, 'pe', 'x86.yarac'))
compile_files(os.path.join(rules_dir, 'pe', 'arm'), os.path.join(install_dir, 'pe', 'arm.yarac'))

# Compile PE32+ signatures.
compile_files(os.path.join(rules_dir, 'pe', 'x64'), os.path.join(install_dir, 'pe', 'x64.yarac'))

# Compile ELF signatures.
compile_files(os.path.join(rules_dir, 'elf', 'x86'), os.path.join(install_dir, 'elf', 'x86.yarac'))
compile_files(os.path.join(rules_dir, 'elf', 'arm'), os.path.join(install_dir, 'elf', 'arm.yarac'))
compile_files(os.path.join(rules_dir, 'elf', 'ppc'), os.path.join(install_dir, 'elf', 'ppc.yarac'))
compile_files(os.path.join(rules_dir, 'elf', 'mips'), os.path.join(install_dir, 'elf', 'mips.yarac'))

# Compile ELF64 signatures.
compile_files(os.path.join(rules_dir, 'elf', 'x64'), os.path.join(install_dir, 'elf', 'x64.yarac'))
compile_files(os.path.join(rules_dir, 'elf', 'arm64'), os.path.join(install_dir, 'elf', 'arm64.yarac'))
compile_files(os.path.join(rules_dir, 'elf', 'ppc64'), os.path.join(install_dir, 'elf', 'ppc64.yarac'))
compile_files(os.path.join(rules_dir, 'elf', 'mips64'), os.path.join(install_dir, 'elf', 'mips64.yarac'))

# Compile Mach-O signatures.
compile_files(os.path.join(rules_dir, 'macho', 'x86'), os.path.join(install_dir, 'macho', 'x86.yarac'))
compile_files(os.path.join(rules_dir, 'macho', 'arm'), os.path.join(install_dir, 'macho', 'arm.yarac'))
compile_files(os.path.join(rules_dir, 'macho', 'ppc'), os.path.join(install_dir, 'macho', 'ppc.yarac'))

# Compile 64-bit Mach-O signatures.
compile_files(os.path.join(rules_dir, 'macho', 'x64'), os.path.join(install_dir, 'macho', 'x64.yarac'))
compile_files(os.path.join(rules_dir, 'macho', 'ppc64'), os.path.join(install_dir, 'macho', 'ppc64.yarac'))

print('signatures compiled successfully')
sys.exit(0)

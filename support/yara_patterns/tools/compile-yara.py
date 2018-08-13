#!/usr/bin/env python3

"""Compile and install tool signatures.
Usage: compile-yara.py yarac-path source-path install-path
"""

import os
import shutil
import subprocess
import sys


def print_help():
    print('Usage: %s yarac-path source-path install-path' % sys.argv[0])


def compile_files(yarac, input_folder, output_folder):
    inputs = []
    for file in os.listdir(input_folder):
        if file.endswith(".yara"):
            inputs.append(os.path.join(input_folder, file))

    if inputs:
        ret = subprocess.call([yarac, '-w'] + inputs + [output_folder])
        if ret != 0:
            print('Error: yarac failed during compilation of file ', path)
            exit(1)


def get_arguments():
    if len(sys.argv) != 4:
        print_help()
        sys.exit(1)
    return sys.argv[1], sys.argv[2], sys.argv[3]


def main():
    yarac, rules_dir, install_dir = get_arguments()

    # Directory paths.
    rules_dir = os.path.join(rules_dir, 'support', 'yara_patterns', 'tools')
    install_dir = os.path.join(install_dir, 'share', 'retdec', 'support', 'generic', 'yara_patterns', 'tools')

    # Remove old files if present.
    if os.path.isfile(install_dir) or os.path.islink(install_dir):
        os.unlink(install_dir)
    else:
        shutil.rmtree(install_dir, ignore_errors=True)

    # Prepare directory structure.
    os.makedirs(os.path.join(install_dir, 'pe'), exist_ok=True)
    os.makedirs(os.path.join(install_dir, 'elf'), exist_ok=True)
    os.makedirs(os.path.join(install_dir, 'macho'), exist_ok=True)

    print('compiling yara signatures...')

    # Compile PE32 signatures.
    compile_files(yarac, os.path.join(rules_dir, 'pe', 'x86'), os.path.join(install_dir, 'pe', 'x86.yarac'))
    compile_files(yarac, os.path.join(rules_dir, 'pe', 'arm'), os.path.join(install_dir, 'pe', 'arm.yarac'))

    # Compile PE32+ signatures.
    compile_files(yarac, os.path.join(rules_dir, 'pe', 'x64'), os.path.join(install_dir, 'pe', 'x64.yarac'))

    # Compile ELF signatures.
    compile_files(yarac, os.path.join(rules_dir, 'elf', 'x86'), os.path.join(install_dir, 'elf', 'x86.yarac'))
    compile_files(yarac, os.path.join(rules_dir, 'elf', 'arm'), os.path.join(install_dir, 'elf', 'arm.yarac'))
    compile_files(yarac, os.path.join(rules_dir, 'elf', 'ppc'), os.path.join(install_dir, 'elf', 'ppc.yarac'))
    compile_files(yarac, os.path.join(rules_dir, 'elf', 'mips'), os.path.join(install_dir, 'elf', 'mips.yarac'))

    # Compile ELF64 signatures.
    compile_files(yarac, os.path.join(rules_dir, 'elf', 'x64'), os.path.join(install_dir, 'elf', 'x64.yarac'))
    compile_files(yarac, os.path.join(rules_dir, 'elf', 'arm64'), os.path.join(install_dir, 'elf', 'arm64.yarac'))
    compile_files(yarac, os.path.join(rules_dir, 'elf', 'ppc64'), os.path.join(install_dir, 'elf', 'ppc64.yarac'))
    compile_files(yarac, os.path.join(rules_dir, 'elf', 'mips64'), os.path.join(install_dir, 'elf', 'mips64.yarac'))

    # Compile Mach-O signatures.
    compile_files(yarac, os.path.join(rules_dir, 'macho', 'x86'), os.path.join(install_dir, 'macho', 'x86.yarac'))
    compile_files(yarac, os.path.join(rules_dir, 'macho', 'arm'), os.path.join(install_dir, 'macho', 'arm.yarac'))
    compile_files(yarac, os.path.join(rules_dir, 'macho', 'ppc'), os.path.join(install_dir, 'macho', 'ppc.yarac'))

    # Compile 64-bit Mach-O signatures.
    compile_files(yarac, os.path.join(rules_dir, 'macho', 'x64'), os.path.join(install_dir, 'macho', 'x64.yarac'))
    compile_files(yarac, os.path.join(rules_dir, 'macho', 'ppc64'), os.path.join(install_dir, 'macho', 'ppc64.yarac'))

    print('signatures compiled successfully')
    sys.exit(0)


if __name__ == "__main__":
    main()

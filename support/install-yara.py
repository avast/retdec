#!/usr/bin/env python3

"""Install all the *.yara files.
Usage: install-yara.py yarac-path install-path yara-patterns-path compile
    yarac-path         Path to the yarac binary to use for YARA rules compilation.
    install-path       Path to the installation directory where to place the results.
    yara-patterns-path Path to the source YARA patterns directory from where to copy (and compile) YARA rules.
    compile            Flag (0|1, ON|OFF, True|False) determining if the YARA rules are to be compiled.
"""

import fnmatch
import multiprocessing.pool
import os
import pathlib
import shutil
import subprocess
import sys
import threading


def print_help():
    print('Usage: %s yarac-path install-path yara-patterns-path compile' % sys.argv[0])


def get_arguments():
    if len(sys.argv) != 5:
        print_help()
        sys.exit(1)
    return sys.argv[1], sys.argv[2], sys.argv[3], (sys.argv[4] == '1' or sys.argv[4].lower() == 'true' or sys.argv[4].lower() == 'on')


def print_arguments(yarac, install_dir, yara_patterns_dir, compile):
    """ Debugging function.
    """
    print('===> yarac path         :', yarac)
    print('===> install path       :', install_dir)
    print('===> yara patterns path :', yara_patterns_dir)
    print('===> compile flag       :', compile)


def copy_yara_patterns(yara_patterns_dir, install_dir):
    """ Copy *.yara files from the given source YARA patterns directory
    to the given installation directory.
    File is copied only if it is newer (timestamp) than already existing
    *.yara[c] file in the installation directory, or if such file does not
    exist.
    """
    for root, dirnames, filenames in os.walk(yara_patterns_dir):
        for filename in fnmatch.filter(filenames, '*.yara'):
            input = os.path.join(root, filename)
            input_suffix = os.path.relpath(input, yara_patterns_dir)

            output = os.path.join(install_dir, 'generic', 'yara_patterns', input_suffix)
            output_c = str(pathlib.Path(output).with_suffix('.yarac'))

            if ((not os.path.isfile(output) and not os.path.isfile(output_c))
                    or (os.path.isfile(output) and os.path.getmtime(output) < os.path.getmtime(input))
                    or (os.path.isfile(output_c) and os.path.getmtime(output_c) < os.path.getmtime(input))):
                print('-- Installing:', output)
                os.makedirs(os.path.dirname(output), exist_ok=True)
                shutil.copy(input, output)


def compile_yara_file(input_file, yarac, install_dir, stdout_lock):
    """ Compile the given .yara file in the given installation directory using
    the provided YARAC program into a *.yarac file.
    Remove the source *.yara file.
    """
    with stdout_lock:
        print('-- Compiling:', input_file)

    output_file = str(pathlib.Path(input_file).with_suffix('.yarac'))
    cmd = [yarac, '-w', input_file, output_file]
    ret = subprocess.call(cmd)
    if ret != 0:
        print('Error: yarac failed during compilation of file', input_file, file=sys.stderr)
        sys.exit(1)

    os.remove(input_file)


def compile_yara_files(yarac, install_dir):
    """ Compile all *.yara files in the given installation directory using the
    provided YARAC program into *.yarac files.
    Remove the source *.yara files.
    """
    inputs = []
    for root, dirnames, filenames in os.walk(install_dir):
        for filename in fnmatch.filter(filenames, '*.yara'):
            inputs.append(os.path.join(root, filename))

    if not inputs:
        return

    stdout_lock = threading.Lock()
    with multiprocessing.pool.ThreadPool() as pool:
        args = [
            (input_file, yarac, install_dir, stdout_lock) for input_file in inputs
        ]
        pool.starmap(compile_yara_file, args)


def main():
    yarac, install_dir, yara_patterns_dir, compile = get_arguments()
    copy_yara_patterns(yara_patterns_dir, install_dir)

    if compile:
        compile_yara_files(yarac, install_dir)

    sys.exit(0)


if __name__ == '__main__':
    main()

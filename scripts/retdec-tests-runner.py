#!/usr/bin/env python3

"""Runs all the installed unit tests."""

import re
import sys
import os
import subprocess

import importlib
config = importlib.import_module('retdec-config')
retdec_utils = importlib.import_module('retdec-utils')

CmdRunner = retdec_utils.CmdRunner


"""First argument can be verbose."""
verbose = False
if len(sys.argv) > 1:
    if sys.argv[1] in ['-v', '--verbose']:
        verbose = True
    else:
        verbose = False


def print_colored(message, color):
    """Emits a colored version of the given message to the standard output (without
    a new line).
       2 string argument are needed:
       $1 message to be colored
       $2 color (red, green, yellow)

    If the color is unknown, it emits just $1.
    """

    if color == 'red':
        print('\033[22;31m' + message + '\033[0m')

    elif color == 'green':
        print('\033[22;32m' + message + '\033[0m')

    elif color == 'yellow':
        print('\033[01;33m' + message + '\033[0m')

    else:
        print(message + '\n')


def unit_tests_in_dir(path):
    """Prints paths to all unit tests in the given directory.
    1 string argument is needed:
        path-path to the directory with unit tests
    """

    tests = []

    for dirpath, _, filenames in os.walk(path):
        for f in filenames:
            if f.startswith('retdec-tests-') and not f.endswith('.sh') and not f.endswith('.py'):
                tests.append(os.path.abspath(os.path.join(dirpath, f)))
                pass

    tests.sort()

    return tests


def print_verbose(output):
    print(output)


def print_non_verbose(output):
    output = output.splitlines()
    p_neg = re.compile(r'(RUN|OK|----------|==========|^$|Running main\(\) from gmock_main.cc)')
    p_passed = re.compile(r'^\[  PASSED  \]')
    p_failed = re.compile(r'^\[  FAILED  \]')
    for line in output:
        if p_neg.search(line) is None:
            if p_passed.search(line):
                print_colored(line, 'green')
            elif p_failed.search(line):
                print_colored(line, 'red')
            else:
                print(line)


def run_unit_tests_in_dir(path):
    """Runs all unit tests in the given directory.
    1 string argument is needed:

        path - path to the directory with unit tests

    Returns 0 if all tests passed, 1 otherwise.
    """

    tests_failed = False
    tests_run = False

    for unit_test in unit_tests_in_dir(path):
        print()
        unit_test_name = os.path.basename(unit_test)
        print_colored(unit_test_name, 'yellow')

        cmd = CmdRunner()
        output, return_code, _ = cmd.run_cmd([unit_test, '--gtest_color=yes'])
        if verbose:
            print_verbose(output)
        else:
            print_non_verbose(output)

        if return_code != 0:
            tests_failed = True
            if return_code >= 127:
                # Segfault, floating-point exception, etc.
                print_colored('FAILED (return code %d)\n' % return_code, 'red')
        tests_run = True

    if tests_failed or not tests_run:
        return 1
    else:
        return 0


if not os.path.isdir(config.UNIT_TESTS_DIR):
    """Run all binaries in unit test dir."""

    sys.stderr.write('error: no unit tests found in %s' % config.UNIT_TESTS_DIR)
    sys.exit(1)

print('Running all unit tests in %s...' % config.UNIT_TESTS_DIR)
sys.exit(run_unit_tests_in_dir(config.UNIT_TESTS_DIR))

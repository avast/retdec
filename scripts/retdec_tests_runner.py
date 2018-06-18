#! /usr/bin/env python3

"""Runs all the installed unit tests."""

import sys
import os
import subprocess

import retdec_config as config

"""First argument can be verbose."""
if sys.argv[1] == '-v' or sys.argv[1] == '--verbose':
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
        $1 path to the directory with unit tests
    """

    tests = []

    for file in os.listdir(path):
        file_name = os.path.basename(file)
        if file_name.startswith('retdec-tests-'):
            tests.append(file)

    tests.sort()

    return tests


def run_unit_tests_in_dir(path):
    """Runs all unit tests in the given directory.
    1 string argument is needed:

        $1 path to the directory with unit tests

    Returns 0 if all tests passed, 1 otherwise.
    """

    tests_failed = False
    tests_run = False

    for unit_test in unit_tests_in_dir(path):
        print()
        unit_test_name = os.path.basename(unit_test)
        print_colored(unit_test_name, 'yellow')
        print()

        # TODO verbose support
        return_code = subprocess.call([unit_test, '--gtest_color=yes'], shell=True)

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

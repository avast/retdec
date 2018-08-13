#!/usr/bin/env python3

"""Runs all the installed unit tests."""

import os
import re
import sys

try:
    import colorama
    colorama.init()
except ImportError:
    # The colorama module is not available, so fall back to output without
    # colors. Instances of the following class can be called, and every
    # attribute is equal to the empty string (this is why it inherits from
    # str).
    class NoColorsColorama(str):
        """Fake implementation of colorama without color support."""
        def __call__(self, *args, **kwargs):
            pass

        def __getattr__(self, _):
            return self
    colorama = NoColorsColorama()
    print("warning: module 'colorama' (https://pypi.python.org/pypi/colorama)",
          "not found, running without color support", file=sys.stderr)

import importlib
config = importlib.import_module('retdec-config')
utils = importlib.import_module('retdec-utils')

CmdRunner = utils.CmdRunner
sys.stdout = utils.Unbuffered(sys.stdout)


def print_colored(message, color=None):
    """Emits a colored version of the given message to the standard output (without
    a new line).

    Arguments:
        message - message to print
        color   - colorama color (if None, no color)
                  can be a combination of color and style (e.g. colorama.Fore.YELLOW+colorama.Style.BRIGHT)
    """
    if color:
        print(color + message + colorama.Style.RESET_ALL)
    else:
        print(message)


def unit_tests_in_dir(path):
    """Prints paths to all unit tests in the given directory.
    Arguments:
        path - path to the directory with unit tests
    """
    tests = []

    for dirpath, _, filenames in os.walk(path):
        for f in filenames:
            if f.startswith('retdec-tests-') and not f.endswith('.py'):
                tests.append(os.path.abspath(os.path.join(dirpath, f)))

    tests.sort()
    return tests


def print_output(output, verbose=False):
    if verbose:
        print(output)
        return

    output = output.splitlines()
    p_neg = re.compile(r'(RUN|OK|----------|==========|^$|Running main\(\) from gmock_main.cc)')
    p_passed = re.compile(r'^\[  PASSED  \]')
    p_failed = re.compile(r'^\[  FAILED  \]')
    for line in output:
        if p_neg.search(line) is None:
            if p_passed.search(line):
                print_colored(line, colorama.Fore.GREEN)
            elif p_failed.search(line):
                print_colored(line, colorama.Fore.RED)
            else:
                print(line)


def run_unit_tests_in_dir(path, verbose=False):
    """Runs all unit tests in the given directory.
    Arguments:

        path    - path to the directory with unit tests
        verbose - print more info

    Returns 0 if all tests passed, 1 otherwise.
    """
    tests_failed = False
    tests_run = False

    for unit_test in unit_tests_in_dir(path):
        print()
        unit_test_name = os.path.basename(unit_test)
        print_colored(unit_test_name, colorama.Fore.YELLOW+colorama.Style.BRIGHT)

        output, return_code, _ = CmdRunner().run_cmd([unit_test, '--gtest_color=yes'], buffer_output=True)
        print_output(output, verbose)

        if return_code != 0:
            tests_failed = True
            print_colored('FAILED (return code %d)\n' % return_code, colorama.Fore.RED)
        tests_run = True

    if tests_failed or not tests_run:
        return 1
    else:
        return 0


def main():
    verbose = len(sys.argv) > 1 and sys.argv[1] in ['-v', '--verbose']

    if not os.path.isdir(config.UNIT_TESTS_DIR):
        utils.print_error_and_die('error: no unit tests found in %s' % config.UNIT_TESTS_DIR)

    print('Running all unit tests in %s...' % config.UNIT_TESTS_DIR)
    sys.exit(run_unit_tests_in_dir(config.UNIT_TESTS_DIR, verbose))


if __name__ == "__main__":
    main()

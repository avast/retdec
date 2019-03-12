#!/usr/bin/env python3

"""Compile all the *.yara files in the given directory into *.yarac.
Remove the original files.
Usage: compile-yara.py yarac-path install-path
"""

import fnmatch
import pathlib
import os
import shutil
import subprocess
import sys


def print_help():
    print('Usage: %s yarac-path install-path' % sys.argv[0])


def get_arguments():
    if len(sys.argv) != 3:
        print_help()
        sys.exit(1)
    return sys.argv[1], sys.argv[2]


def main():
    yarac, install_dir = get_arguments()

    inputs = []
    for root, dirnames, filenames in os.walk(install_dir):
        for filename in fnmatch.filter(filenames, '*.yara'):
            inputs.append(os.path.join(root, filename))

    for i in inputs:
        fn = pathlib.Path(i)
        o = fn.with_suffix('.yarac')

        print('Compiling:', i, '...')
        cmd = [yarac, '-w'] + [i] + [str(o)]
        ret = subprocess.call(cmd)
        if ret != 0:
            print('Error: yarac failed during compilation of file ', path)
            exit(1)

        os.remove(i)

    sys.exit(0)


if __name__ == '__main__':
    main()

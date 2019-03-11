#!/usr/bin/env python3

"""Compile all the *.yara files in the given directory into *.yarac.
Remove the original files.
Usage: compile-yara.py yarac-path install-path
"""

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
    print('==============> yarac   = ', yarac)
    print('==============> install = ', install_dir)
    sys.exit(0)


if __name__ == '__main__':
    main()

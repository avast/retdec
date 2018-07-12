#! /usr/bin/env python3

"""Generator of JSON files containing C-types information for C standard library and other header files in /usr/include/ directory."""

import argparse
import shutil
import sys
import os
import subprocess
import glob

#
# C standard library headers.
#
CSTDLIB_HEADERS = [
	'assert.h',
	'complex.h',
	'ctype.h',
    'errno.h',
    'fenv.h',
    'float.h',
    'inttypes.h',
    'iso646.h',
    'limits.h',
    'locale.h',
    'math.h',
    'setjmp.h',
    'signal.h',
    'stdalign.h',
    'stdarg.h',
    'stdatomic.h',
    'stdbool.h',
    'stddef.h',
    'stdint.h',
    'stdio.h',
    'stdlib.h',
    'stdnoreturn.h',
    'string.h',
    'tgmath.h',
    'threads.h',
    'time.h',
    'uchar.h',
    'wchar.h',
    'wctype.h'
]

#
# Files we don't want in JSONs.
#
FILES_PATTERNS_TO_FILTER_OUT=[
	'GL/',
    'Qt.*/',
    'SDL.*/',
    'X11/',
    'alsa/',
    'c\\+\\+/',
    'dbus.*/',
    'glib.*/',
    'libdrm/',
    'libxml2/',
    'llvm.*/',
    'mirclient/',
    'php[0-9.-]*/',
    'pulse/',
    'python.*/',
    'ruby.*/',
    'wayland.*/',
    'xcb/'
]

#SEP = '\\|'
FILES_FILTER = '|'.join(FILES_PATTERNS_TO_FILTER_OUT)
#FILES_FILTER = (FILES_FILTER:Expand.hash()SEP)

#
# Paths.
#
SCRIPT_DIR  =  os.path.dirname(os.path.abspath(__file__))
SCRIPT_NAME  =  __name__
EXTRACTOR = os.path.join(SCRIPT_DIR, 'extract_types.py')
MERGER = os.path.join(SCRIPT_DIR, 'merge_jsons.py')
INCLUDE_DIR = '/usr/include/'
OUT_DIR =  '.'
STD_LIB_OUT_DIR = os.path.join(OUT_DIR, 'gen_tmp_cstdlib')
STD_LIB_JSON = os.path.join(OUT_DIR, 'cstdlib.json')
LINUX_OUT_DIR = os.path.join(OUT_DIR, 'gen_tmp_linux')
LINUX_JSON = os.path.join(OUT_DIR, 'linux.json')
CSTDLIB_PRIORITY_OUT_DIR = os.path.join(OUT_DIR, 'gen_tmp_cstdlib_priority')
LINUX_PRIORITY_OUT_DIR = os.path.join(OUT_DIR, 'gen_tmp_linux_priority')

def parse_args():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('-i', '--json-indent',
                        dest='json_indent',
                        default=1,
                        help='Set indentation in JSON files.')

    parser.add_argument('-f', '--files-filter',
                        dest='file_filter',
                        help='Pattern to ignore specific header files.')

    parser.add_argument('-n', '--no-cleanup',
                        dest='no_cleanup',
                        default=True,
                        action='store_true',
                        help='Do not remove dirs with JSONs for individual header files.')

    parser.add_argument('--cstdlib-headers',
                        dest='cstdlib_headers',
                        help='Set path to the C standard library headers with high-priority types info.')

    parser.add_argument('--linux-headers',
                        dest='linux_headers',
                        help='Set path to the Linux headers with high-priority types info.')

    return parser.parse_args()


args = parse_args()

#
# Prints the given error message ($1) to stderr and exits.
#
def print_error_and_die (error) :
    sys.stderr.write('Error: ' + error)
    sys.exit(1)

def remove_dir(path):
    if os.path.isdir(path) and not os.path.islink(path):
        shutil.rmtree(path)
    elif os.path.exists(path):
        os.remove(path)

#
# Initial cleanup.
#
remove_dir(STD_LIB_OUT_DIR)
os.mkdir(STD_LIB_OUT_DIR)
remove_dir(LINUX_OUT_DIR)
os.mkdir(LINUX_OUT_DIR)
remove_dir(CSTDLIB_PRIORITY_OUT_DIR)
os.mkdir(CSTDLIB_PRIORITY_OUT_DIR)
remove_dir(LINUX_PRIORITY_OUT_DIR)
os.mkdir(LINUX_PRIORITY_OUT_DIR)

#
# Generate JSONs for whole /usr/include path.
# Filter out unwanted headers.
# Move standard headers to other dir.
#

if args.file_filter:
    FILES_FILTER += '|' + args.file_filter

subprocess.call([EXTRACTOR, INCLUDE_DIR, '-o', LINUX_OUT_DIR], shell = True)
FILES_FILTER = (FILES_FILTER//\//_)
subprocess.call(['find', LINUX_OUT_DIR + '/', '-regex', LINUX_OUT_DIR + '/.*\(' + FILES_FILTER + '\).*', '-delete'], shell = True)
#
# Move standard library headers to other directory.
# Edit standard header paths to look like type-extractor generated jsons.
#
for header in CSTDLIB_HEADERS:
    for f in os.popen('find \'' + INCLUDE_DIR + '\' -name \'' + header + '\'').read().rip('\n'):
        f  =  (f#INCLUDE_DIR)
        f  =  (f////_)
        f  =  (f/%\.h/.json)
        if os.path.isfile(LINUX_OUT_DIR + '/' + f):
            shutil.move(LINUX_OUT_DIR + '/' + f, STD_LIB_OUT_DIR)

#
# Extract types info from high-priority cstdlib and linux headers if paths were given.
#
if args.cstdlib_headers:
    subprocess.call([EXTRACTOR, args.cstdlib_headers, '-o', CSTDLIB_PRIORITY_OUT_DIR], shell = True)
if args.linux_headers:
    subprocess.call([EXTRACTOR, args.linux_headers, '-o', LINUX_PRIORITY_OUT_DIR], shell = True)

#
# Merging.
# Priority headers must be first.
# Cstdlib priority headers are merged to the C standard library JSON,
# Linux priority headers to the Linux JSON.
#
subprocess.call([MERGER, CSTDLIB_PRIORITY_OUT_DIR, STD_LIB_OUT_DIR, '-o', STD_LIB_JSON, '--json-indent', args.json_indent], shell = True)
subprocess.call([MERGER, LINUX_PRIORITY_OUT_DIR, LINUX_OUT_DIR, '-o', LINUX_JSON, '--json-indent', args.json_indent], shell = True)
#
# Optional cleanup at the end.
#
if not args.no_cleanup:
    remove_dir(STD_LIB_OUT_DIR)
    remove_dir(LINUX_OUT_DIR)
    remove_dir(args.cstdlib_headers)
    remove_dir(CSTDLIB_PRIORITY_OUT_DIR)
    remove_dir(args.linux_headers)

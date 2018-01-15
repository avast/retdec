#!/usr/bin/env python3
"""Extracts types info from header files.

Parses function declarations, structs, unions and enums.

The input has to be path to file.[h|H] or directory.
"""

import functools
import logging
import multiprocessing
import os
import re
import sys

import type_extractor.io
from type_extractor.arg_parser import get_arg_parser_for_extract_types
from type_extractor.io import read_text_file
from type_extractor.parse_includes import get_types_info_from_text
from type_extractor.utils import get_files_with_suffix_from_path
from type_extractor.utils import setup_logging


def parse_args():
    """Parses script arguments and returns them."""
    parser = get_arg_parser_for_extract_types(__doc__)
    return parser.parse_args()


def get_output_file(header, path, out_format, dir_out):
    """Creates unique name for output file.

    Use relative path and substitute path separator for underscore.
    """
    if os.path.isfile(path):
        f_name = os.path.basename(path)
    else:
        header_rel_path = os.path.relpath(header, path)
        f_name = re.sub(re.escape(os.path.sep), '_', header_rel_path).strip('_')
    f_name = re.sub(r'\.(h|H)$', '.' + out_format, f_name)

    return os.path.join(dir_out, f_name)


def parse_header(header_file, path, output_handler, output_dir, output_format, indent):
    """Get types information from header file and writes output in chosen
    format to file to output directory.

    Path to header set to functions is relative path from script's input path.
    """
    logging.info('Reading file: {}'.format(header_file))
    content = read_text_file(header_file)
    if os.path.isfile(path):
        relative_path = os.path.basename(path)
    else:
        relative_path = os.path.relpath(header_file, path)

    functions, types, structs, unions, enums = get_types_info_from_text(
        relative_path, content, output_format)

    out_f = get_output_file(header_file, path, output_format, output_dir)
    with open(out_f, 'w') as output_file:
        output_handler(
            output_file, functions, types, structs, unions, enums, indent
        )


def main(args):
    os.makedirs(args.output, exist_ok=True)
    dir_out = os.path.abspath(args.output)

    output_handler = getattr(
        type_extractor.io,
        'print_types_info_{}'.format(args.format)
    )

    indent = args.json_indent

    for path in args.path:
        with multiprocessing.Pool() as pool:
            pool.map(
                functools.partial(
                    parse_header,
                    path=path,
                    output_handler=output_handler,
                    output_dir=dir_out,
                    output_format=args.format,
                    indent=indent
                ),
                get_files_with_suffix_from_path(path, ('.h', '.H'))
            )


# We have to parse arguments and setup logging here because of the way the
# multiprocessing module works on Windows.
args = parse_args()
setup_logging(enable=args.enable_logging)

if __name__ == '__main__':
    sys.exit(main(args))

#!/usr/bin/env python3
"""Merges json files to one, solves conflicts in typedefs and structs."""

import logging
import sys

from type_extractor.arg_parser import get_arg_parser_for_merge_jsons
from type_extractor.io import print_types_functions_json
from type_extractor.merge_files import merge_json_file
from type_extractor.remove_json_types import remove_unused_json_types
from type_extractor.utils import get_files_with_suffix_from_path
from type_extractor.utils import setup_logging


def parse_args():
    """Parses script arguments and returns them."""
    parser = get_arg_parser_for_merge_jsons(__doc__)
    return parser.parse_args()


def main(args):
    merged_types = {}
    merged_functions = {}

    for path in args.path:
        for json_file in get_files_with_suffix_from_path(path, '.json'):
            logging.info('Merging json file {}'.format(json_file))
            merge_json_file(merged_types, merged_functions, json_file)

    if not args.keep_unused_types:
        merged_types = remove_unused_json_types(merged_functions, merged_types)

    logging.info('Writing output to: {}'.format(args.output))
    with open(args.output, 'w') as output_file:
        print_types_functions_json(
            output_file, merged_types, merged_functions, args.json_indent)


# We have to parse arguments and setup logging here because of the way the
# multiprocessing module works on Windows.
args = parse_args()
setup_logging(enable=args.enable_logging)

if __name__ == '__main__':
    sys.exit(main(args))

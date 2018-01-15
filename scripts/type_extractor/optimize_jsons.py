#!/usr/bin/env python3
"""1. Substitutes SHA1 hash in JSONs with natural numbers.
C types in different files will have different keys, therefore you shoud not
try to merge them!
2. Removes qualifier types.
"""

import multiprocessing
import sys

from type_extractor.arg_parser import get_arg_parser_for_optimize_jsons
from type_extractor.io import load_json_file
from type_extractor.io import print_json_file
from type_extractor.remove_json_types import remove_qualifier_json_types
from type_extractor.substitute_json_keys import substitute_json_keys_with_natural_numbers
from type_extractor.utils import get_files_with_suffix_from_all_paths


def parse_args():
    """Parses script arguments and returns them."""
    parser = get_arg_parser_for_optimize_jsons(__doc__)
    return parser.parse_args()


def optimize_json(json_file):
    content = load_json_file(json_file)

    substitute_json_keys_with_natural_numbers(content)
    remove_qualifier_json_types(content)

    with open(json_file, 'w') as out:
        print_json_file(out, content, args.json_indent)


def main(args):
    with multiprocessing.Pool() as pool:
        pool.map(
            optimize_json,
            get_files_with_suffix_from_all_paths(args.path, '.json')
        )


# We have to parse arguments and setup logging here because of the way the
# multiprocessing module works on Windows.
args = parse_args()

if __name__ == '__main__':
    sys.exit(main(args))

"""Script's arguments parsing."""

import argparse

from .io import get_output_format_options


class GetJsonIndent(argparse.Action):
    """Parses json-indent argument. Json takes ints and strings as indent."""

    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        if nargs is not None:
            raise ValueError('nargs not allowed')
        super(GetJsonIndent, self).__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, value, option_string=None):
        """Sets correct indent. For empty indent sets Null to not print new lines."""
        try:
            indent = int(value)
        except:
            indent = value

        if not indent:
            indent = None
        setattr(namespace, self.dest, indent)


def get_arg_parser_for_extract_types(doc):
    """Creates and returns argument parser."""
    parser = argparse.ArgumentParser(
        description=doc,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        '-l', '--enable-logging', dest='enable_logging',
        action='store_true', default=False,
        help='enable emission of logging info'
    )
    parser.add_argument(
        '-f', '--format', dest='format',
        action='store', choices=get_output_format_options(),
        default='json', help='choose output format of parsing'
    )
    parser.add_argument(
        '-o', '--output', dest='output',
        default='type_extractor_output', help='choose output directory'
    )
    parser.add_argument(
        '--json-indent', dest='json_indent', action=GetJsonIndent,
        default=4, help='choose indentation for json files'
    )
    parser.add_argument(
        'path', metavar='PATH', nargs='+',
        help='path to file or dir to extract types'
    )
    return parser


def get_arg_parser_for_merge_jsons(doc):
    """Creates and returns argument parser."""
    parser = argparse.ArgumentParser(
        description=doc,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        '-l', '--enable-logging', dest='enable_logging',
        action='store_true', default=False,
        help='enable emission of logging info'
    )
    parser.add_argument(
        '-o', '--output', dest='output',
        default='merge_output.json', help='choose output file'
    )
    parser.add_argument(
        '--json-indent', dest='json_indent', action=GetJsonIndent,
        default=4, help='choose indentation for json files'
    )
    parser.add_argument(
        '--keep-unused-types', dest='keep_unused_types',
        action='store_true', default=False,
        help='type not used in any function is removed by default'
    )
    parser.add_argument(
        'path', metavar='PATH', nargs='+',
        help='path to json file or dir with json files'
    )
    return parser


def get_arg_parser_for_optimize_jsons(doc):
    """Creates and returns argument parser."""
    parser = argparse.ArgumentParser(
        description=doc,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        '--json-indent', dest='json_indent', action=GetJsonIndent,
        default=4, help='choose indentation for json files'
    )
    parser.add_argument(
        'path', metavar='PATH', nargs='+',
        help='path to json file or dir with json files'
    )
    return parser

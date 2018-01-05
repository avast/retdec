"""Utilities."""

import logging
import os


def get_files_with_suffix_from_all_paths(paths, suffix=''):
    """For all paths returns path if it's file.
    Otherwise recursively walks path and returns all files with given suffix.
    """
    for path in paths:
        for f in get_files_with_suffix_from_path(path, suffix):
            yield f


def get_files_with_suffix_from_path(path, suffix=''):
    """Returns path if it's file. Otherwise recursively walks path and returns all
    files with given suffix.
    """
    if os.path.isfile(path) and path.endswith(suffix):
        yield path
    else:
        for dir_path, _, file_list in os.walk(path):
            for fname in sorted(file_list):
                if fname.endswith(suffix):
                    yield os.path.join(dir_path, fname)


def setup_logging(enable):
    """Sets up the logging facilities."""
    if enable:
        logging.basicConfig(level=logging.INFO,
                            format='%(asctime)s %(levelname)s: %(message)s')
    else:
        logging.disable(logging.CRITICAL)


def object_attr_string_repr(attr):
    """Returns string representation of attr."""
    return str(attr) if attr is not None else ''

"""Merges json objects, solves types' conflicts."""

from .io import load_json_file
from .json_types import TYPES


def typedef_loops_with_already_inserted_typedefs(new_type, merged_types):
    """Checks if new type would create circular typedefs in merged_types."""
    if new_type['typedefed_type'] not in merged_types:
        return False
    aliased_type = merged_types[new_type['typedefed_type']]
    new_type_name = new_type['name']

    while aliased_type['type'] == TYPES.TYPEDEF.value:
        if new_type_name == aliased_type['name']:
            return True
        if aliased_type['typedefed_type'] not in merged_types:
            return False
        aliased_type = merged_types[aliased_type['typedefed_type']]

    return False


def choose_one_type(existing_type, new_type, merged):
    """Chooses one representation of data type when they are duplicit."""
    if existing_type['type'] == TYPES.STRUCT.value:    # they should be of the same type
        if not existing_type['members']:   # we want struct with members
            return new_type                # not the one used as e.g. func parameter
        else:
            return existing_type

    if existing_type['type'] == TYPES.UNION.value:    # same as structures
        if existing_type['members'] == []:
            return new_type
        else:
            return existing_type

    if (existing_type['type'] == TYPES.TYPEDEF.value and
            new_type['type'] == TYPES.TYPEDEF.value):
        if existing_type['typedefed_type'] == 'unknown':
            if typedef_loops_with_already_inserted_typedefs(new_type, merged):
                return existing_type
            else:
                return new_type

    return existing_type  # not typedef or struct - types are same


def merge_types(merged, new):
    for type_hash, t_type in new.items():
        if type_hash in merged:
            merged[type_hash] = choose_one_type(merged[type_hash], t_type, merged)
        else:
            merged[type_hash] = t_type


def merge_functions(merged, new):
    for func_name, func in new.items():
        if func_name not in merged:
            merged[func_name] = func


def merge_json_file(merged_types, merged_functions, json_file):
    content = load_json_file(json_file)
    types = content['types']
    functions = content['functions']
    merge_types(merged_types, types)
    merge_functions(merged_functions, functions)

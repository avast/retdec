"""Removes types that are not used by any function and qualifier types."""


from .json_types import TYPES


def remove_unused_json_types(functions, old_types):
    """Removes types that are not used by any function."""
    new_types = {}
    for _, func in functions.items():
        add_type_to_new_types(func['ret_type'], old_types, new_types)
        add_params_to_new_types(func['params'], old_types, new_types)
    return new_types


def add_params_to_new_types(params, old_types, new_types):
    for p in params:
        add_type_to_new_types(p['type'], old_types, new_types)


def add_type_to_new_types(type_key, old_types, new_types):
    if type_key in new_types:
        return

    type = old_types[type_key]
    new_types[type_key] = type
    type_of_type = type['type']
    if type_of_type == TYPES.ARRAY.value:
        add_array_to_new_types(type, old_types, new_types)
    elif type_of_type == TYPES.FUNCTION.value:
        add_function_type_to_new_types(type, old_types, new_types)
    elif type_of_type == TYPES.POINTER.value:
        add_pointer_to_new_types(type, old_types, new_types)
    elif type_of_type == TYPES.QUALIFIER.value:
        add_qualifier_to_new_types(type, old_types, new_types)
    elif (type_of_type == TYPES.STRUCT.value or
            type_of_type == TYPES.UNION.value):
        add_composite_type_members_to_new_types(type, old_types, new_types)
    elif type_of_type == TYPES.TYPEDEF.value:
        add_typedef_to_new_types(type, old_types, new_types)
    # integral_type, floating_point_type, enum, void are terminal,
    # they do not point to other type


def add_array_to_new_types(type, old_types, new_types):
    add_type_to_new_types(type['element_type'], old_types, new_types)


def add_function_type_to_new_types(type, old_types, new_types):
    add_type_to_new_types(type['ret_type'], old_types, new_types)
    add_params_to_new_types(type['params'], old_types, new_types)


def add_pointer_to_new_types(type, old_types, new_types):
    add_type_to_new_types(type['pointed_type'], old_types, new_types)


def add_qualifier_to_new_types(type, old_types, new_types):
    add_type_to_new_types(type['modified_type'], old_types, new_types)


def add_composite_type_members_to_new_types(type, old_types, new_types):
    for m in type['members']:
        add_type_to_new_types(m['type'], old_types, new_types)


def add_typedef_to_new_types(type, old_types, new_types):
    if type['typedefed_type'] != 'unknown':
        add_type_to_new_types(type['typedefed_type'], old_types, new_types)


def remove_qualifier_json_types(content):
    qualifier_types, other_types = split_types_to_qualifiers_and_others(content['types'])
    content['types'] = other_types
    qualifier_types = get_qualified_types(qualifier_types)
    substitute_qualifier_types_in_functions(content['functions'], qualifier_types)
    substitute_qualifier_types_in_types(content['types'], qualifier_types)


def split_types_to_qualifiers_and_others(types):
    qualifier_types = {}
    other_types = {}
    for k, t in types.items():
        if t['type'] == TYPES.QUALIFIER.value:
            qualifier_types[k] = t
        else:
            other_types[k] = t
    return qualifier_types, other_types


def get_qualified_types(qualifier_types):
    """We want all qualifiers to point to non qualifier types.

    There are sometimes e.g. 'const restrict int' types. We want
    the 'const' type point to 'int', not 'restrict'.
    Returns dictionary {qualifier_type: modified_non_qualifier_type}.
    """
    non_qualifier_types = {}
    for k, t in qualifier_types.items():
        modified_type = t['modified_type']
        while modified_type in qualifier_types:
            modified_type = qualifier_types[modified_type]['modified_type']
        non_qualifier_types[k] = modified_type
    return non_qualifier_types


def substitute_qualifier_types_in_functions(functions, qualifier_types):
    for _, f in functions.items():
        ret_type = f['ret_type']
        if ret_type in qualifier_types:
            f['ret_type'] = qualifier_types[ret_type]
        substitute_qualifier_types_in_params(f['params'], qualifier_types)


def substitute_qualifier_types_in_params(params, qualifier_types):
    for p in params:
        param_type = p['type']
        if param_type in qualifier_types:
            p['type'] = qualifier_types[param_type]


def substitute_qualifier_types_in_types(types, qualifier_types):
    for _, type in types.items():
        type_of_type = type['type']
        if type_of_type == TYPES.ARRAY.value:
            substitute_qualifier_type_in_array(type, qualifier_types)
        elif type_of_type == TYPES.FUNCTION.value:
            substitute_qualifier_types_in_function_type(type, qualifier_types)
        elif type_of_type == TYPES.POINTER.value:
            substitute_qualifier_type_in_pointer(type, qualifier_types)
        elif (type_of_type == TYPES.STRUCT.value or
                type_of_type == TYPES.UNION.value):
            substitute_qualifier_types_in_members(type, qualifier_types)
        elif type_of_type == TYPES.TYPEDEF.value:
            substitute_qualifier_type_in_typedef(type, qualifier_types)


def substitute_qualifier_type_in_array(type, qualifier_types):
    element_type = type['element_type']
    if element_type in qualifier_types:
        type['element_type'] = qualifier_types[element_type]


def substitute_qualifier_types_in_function_type(type, qualifier_types):
    ret_type = type['ret_type']
    if ret_type in qualifier_types:
        type['ret_type'] = qualifier_types[ret_type]
    substitute_qualifier_types_in_params(type['params'], qualifier_types)


def substitute_qualifier_type_in_pointer(type, qualifier_types):
    pointed_type = type['pointed_type']
    if pointed_type in qualifier_types:
        type['pointed_type'] = qualifier_types[pointed_type]


def substitute_qualifier_types_in_members(type, qualifier_types):
    for m in type['members']:
        member_type = m['type']
        if member_type in qualifier_types:
            m['type'] = qualifier_types[member_type]


def substitute_qualifier_type_in_typedef(type, qualifier_types):
    typedefed_type = type['typedefed_type']
    if typedefed_type != 'unknown' and typedefed_type in qualifier_types:
        type['typedefed_type'] = qualifier_types[typedefed_type]

"""Substitutes all types' keys in JSON with natural numbers."""


from .json_types import TYPES


def substitute_json_keys_with_natural_numbers(content):
    new_keys = generate_new_keys(content['types'])
    substitute_json_keys(content, new_keys)


def substitute_json_keys(content, new_keys):
    """Substitutes json keys in content with new keys."""
    substitute_keys_in_functions(content['functions'], new_keys)
    new_types = substitute_keys_in_types(content['types'], new_keys)
    content['types'] = new_types


def generate_new_keys(old_keys):
    """Returns dictionary where key is old json key and value is the new key."""
    new_keys = {}
    for new, old in enumerate(sorted(old_keys), 1):
        new_keys[old] = str(new)  # key in JSON object is always string
    return new_keys


def substitute_keys_in_functions(functions, new_keys):
    """Substitutes all old keys in return type and parameter types with new keys."""
    for _, func in functions.items():
        func['ret_type'] = new_keys[func['ret_type']]
        substitute_params_keys(func['params'], new_keys)


def substitute_params_keys(params, new_keys):
    """Substitutes all old keys in parameter types with new keys."""
    for p in params:
        p['type'] = new_keys[p['type']]


def substitute_keys_in_types(old_types, new_keys):
    """Substitutes all old keys in 'types' part of JSON."""
    new_types = {}
    for k, t in old_types.items():
        new_types[new_keys[k]] = t
        substitute_type_keys(t, new_keys)
    return new_types


def substitute_type_keys(type, new_keys):
    """Substitutes all old keys in one JSON type."""
    type_of_type = type['type']
    if type_of_type == TYPES.ARRAY.value:
        substitute_array_keys(type, new_keys)
    elif type_of_type == TYPES.FUNCTION.value:
        substitute_function_type_keys(type, new_keys)
    elif type_of_type == TYPES.POINTER.value:
        substitute_pointer_keys(type, new_keys)
    elif type_of_type == TYPES.QUALIFIER.value:
        substitute_qualifier_keys(type, new_keys)
    elif (type_of_type == TYPES.STRUCT.value or
            type_of_type == TYPES.UNION.value):
        substitute_composite_type_members_keys(type, new_keys)
    elif type_of_type == TYPES.TYPEDEF.value:
        substitute_typedefed_type_keys(type, new_keys)


def substitute_array_keys(type, new_keys):
    type['element_type'] = new_keys[type['element_type']]


def substitute_function_type_keys(type, new_keys):
    type['ret_type'] = new_keys[type['ret_type']]
    substitute_params_keys(type['params'], new_keys)


def substitute_pointer_keys(type, new_keys):
    type['pointed_type'] = new_keys[type['pointed_type']]


def substitute_qualifier_keys(type, new_keys):
    type['modified_type'] = new_keys[type['modified_type']]


def substitute_composite_type_members_keys(type, new_keys):
    for m in type['members']:
        m['type'] = new_keys[m['type']]


def substitute_typedefed_type_keys(type, new_keys):
    if type['typedefed_type'] != 'unknown':
        type['typedefed_type'] = new_keys[type['typedefed_type']]

"""I/O functions."""

import json
import re

from .json_types import convert_enums_to_type_for_json
from .json_types import convert_func_types_to_type_for_json
from .json_types import convert_structs_to_type_for_json
from .json_types import convert_typedefs_to_type_for_json
from .json_types import convert_unions_to_type_for_json
from .lti_types import LTI_TYPES


def read_text_file(file_path):
    """Reads all the data from the given text file and returns them as a
    string.
    """
    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        return f.read()


def load_json_file(json_file):
    """Loads the data from the given json file, returns them as dict."""
    with open(json_file, 'r') as j_file:
        return json.load(j_file)


def types_functions_to_json(json_types, functions):
    """Creates string for JSON output from types and functions."""
    return {'functions': functions, 'types': json_types}


def print_types_functions_json(f_out, json_types, functions, indent=4):
    output = types_functions_to_json(json_types, functions)
    print_json_file(f_out, output, indent)


def print_json_file(f_out, content, indent=4, sort_keys=True):
    print(
        json.dumps(content, default=JSONHandler, indent=indent, sort_keys=sort_keys),
        file=f_out
    )


def print_types_info_json(f_out, functions, typedefs, structs, unions, enums, indent=4):
    """JSON output for types and functions."""
    json_types = {}
    convert_typedefs_to_type_for_json(typedefs, json_types)
    convert_enums_to_type_for_json(enums, json_types)
    convert_func_types_to_type_for_json(functions, json_types)
    convert_structs_to_type_for_json(structs, json_types)
    convert_unions_to_type_for_json(unions, json_types)

    print_types_functions_json(f_out, json_types, functions, indent)


def JSONHandler(obj):
    if hasattr(obj, 'repr_json'):
        return obj.repr_json()

    raise TypeError('Object of type {} with value of {} is not JSON '
                    'serializable'.format(type(obj), repr(obj)))


def print_types_info_txt(f_out, functions, typedefs, structs, unions, enums, ident=4):
    """Text output for types and functions."""
    for sname, sinfo in structs.items():
        f_out.write('Struct' + '\n')
        f_out.write('Name: ' + sinfo.name_text + '\n')
        if sinfo.type_name_text:
            f_out.write('Typedef name: ' + sinfo.type_name_text + '\n')
        f_out.write('Data:' + '\n')
        for member in sinfo.members_list:
            f_out.write('Name: {}\ttype: {}'.format(member.name_text,
                        member.type_text))
            if hasattr(member, 'size'):
                f_out.write(' size: {}\n'.format(member.size))
            else:
                f_out.write('\n')
        f_out.write('\n')

    for fname, f_info in functions.items():
        f_out.write(f_info.decl + '\n')
        f_out.write('Name: ' + f_info.name + '\n')
        f_out.write('Return type: ' + f_info.ret_type_text + '\n')
        f_out.write('Parameters:' + '\n')
        for p in f_info.params:
            f_out.write('Name: {}\t\ttype: {} {}'.format(p.name_text,
                        p.type_text, p.annotations_text) + '\n')
        if f_info.vararg:
            f_out.write('Varargs: True' + '\n')
        f_out.write('\n')


def print_types_info_lti(f_out, functions, types, structs, unions, enums, indent=0):
    """Lti output for types and functions."""
    for sname, sinfo in sorted(structs.items()):
        lti = '%struct.' + sname + ' = type { '
        lti = lti + ', '.join([str_types_sub(members.type_text, members.name_text)
                              for members in sinfo.members_list])
        lti = lti + ' }\n'
        f_out.write(lti)

    for fname, f_info in sorted(functions.items()):
        lti_1 = f_info.name_text+' '+str_types_sub(f_info.ret_type_text, '')
        lti_2 = ' ' + str(len(f_info.params_list)) + ' '
        lti_3 = ', '.join([str_types_sub(param.type_text, param.name_text)
                          for param in f_info.params_list])
        lti_4 = ' # ' + f_info.decl
        lti = lti_1 + lti_2 + lti_3 + lti_4
        f_out.write(lti + '\n')


def types_sub(type_text):
    """Substitutes type for lti type."""
    if type_text in LTI_TYPES.keys():
        return LTI_TYPES[type_text]
    return type_text


def str_types_sub(type_text, name):
    """Substitutes type made of few basic types."""
    if '[' in type_text:
        return array_sub(type_text)

    return str_types_sub_no_array(type_text)


def array_sub(type_text):
    """Creates lti format of arrays e.g. 'type [N]' =>  '[N x type]'."""
    num = re.search(r'\[(\d+)\]', type_text)
    if num is None:
        return type_text
    type_text = re.sub(r'\s*\[.*\]', '', type_text)
    num = num.group(1)
    return '[' + num + ' x ' + str_types_sub_no_array(type_text) + ']'


def str_types_sub_no_array(type_text):
    """Creates lti format for types, expect no arrays."""
    type_text = re.sub(r'const', ' ', type_text).strip()
    type_text = re.sub(r'(un)?signed', ' ', type_text).strip()
    if type_text in LTI_TYPES.keys():
        return LTI_TYPES[type_text]

    if '*' in type_text:
        type_text_nptr = re.sub(r'\s*\*+\s*', '', type_text)
        if type_text_nptr in LTI_TYPES.keys():
            return LTI_TYPES[type_text_nptr] + '*' * type_text.count('*')

    return ''.join([types_sub(item) for item in type_text.split(' ')])


def get_output_format_options():
    return ['txt', 'lti', 'json']

"""Parses struct and union definitions in header file.

Expects file content without comments and preprocessor definitions.
"""

import re

from .params_info import Param
from .params_info import parse_one_param
from .params_info import split_param_to_type_and_name
from .parse_enums import parse_enum
from .utils import object_attr_string_repr


class CompositeType(object):
    """Representation of composite info."""

    def __init__(self, name=None, type_name=None,
                 members=None, header=None):
        """Constructs composite type info."""
        self.name = name
        self.type_name = type_name
        self.members = members if members is not None else []
        self.header = header

    @property
    def name_text(self):
        """Returns type's name."""
        return object_attr_string_repr(self.name)

    @property
    def type_name_text(self):
        """Returns a textual representation of the typedef name."""
        return object_attr_string_repr(self.type_name)

    @property
    def members_list(self):
        """Returns list of type's parameters."""
        return self.members if self.members is not None else []

    @property
    def header_text(self):
        """Returns a textual representation of header file."""
        return object_attr_string_repr(self.header)

    def __repr__(self):
        return '{}({!r}, {!r})'.format(
               self.__class__.__name__, self.name_text, self.members)

    def repr_json(self):
        return self.__dict__

    def __eq__(self, other):
        return (self.name == other.name and
                self.type_name == other.type_name and
                self.members == other.members)

    def __ne__(self, other):
        return not self == other


class Struct(CompositeType):
    pass


class Union(CompositeType):
    pass


def get_all_structs(text):
    "Gets all struct definitions from text."""
    return get_all_composite_types(text, 'struct')


def get_all_unions(text):
    """Gets all union definitions from text."""
    return get_all_composite_types(text, 'union')


def get_all_composite_types(text, to_get='struct'):
    """Gets all struct or union definitions from text.

    Typedefed contains typedef keyword.
    """
    types_list = []
    type_re = r'(?:typedef\s+)?%s[\w\s:]*?\{(?:.*?\}[\w\s\*,]*?;){%d}'
    x = 1
    found = re.search(type_re % (to_get, x), text)
    if found is None:
        return text, types_list
    one_type = re.escape(found.group(0))
    while one_type:
        while one_type.count('{') != one_type.count('}'):
            x = x+1
            found = re.search(type_re % (to_get, x), text)
            if found is None:
                return text, types_list
            if x > 20:
                one_type = re.escape(found.group(0))
                break
            one_type = re.escape(found.group(0))
        text = re.sub(one_type, ';', text, count=1)
        if '<' not in found.group(0) and '::' not in found.group(0):
            types_list.append(found.group(0))
        x = 1
        found = re.search(type_re % (to_get, x), text)
        if found is None:
            return text, types_list
        one_type = re.escape(found.group(0))


def parse_struct(struct, hfile):
    return parse_composite_type(struct, hfile, Struct)


def parse_union(union, hfile):
    return parse_composite_type(union, hfile, Union)


def parse_composite_type(type_str, hfile, parsed_type=Struct):
    """Composite type may be struct or union (even typedefed with typedef
    keyword).

    Returns Struct or Union object.
    """
    names_and_members = re.search(
        r'^(?:typedef\s+)?(?:struct|union)([\w\s]*?)\{(.*)\}([\w\s\*,]*);',
        type_str
    )
    if names_and_members is None:
        return parsed_type('', '', [], hfile)
    name = names_and_members.group(1).strip()
    if type_str.startswith('typedef'):
        typedef_name = names_and_members.group(3).strip()
    else:
        typedef_name = ''
    members_str = names_and_members.group(2)
    members = split_members(members_str)
    parsed_members = []
    for m in members:
        one_member = Param('', m)
        parsed_members.append(one_member)
        edit_structured_param_type(one_member, parsed_members, hfile)
    return parsed_type(name, typedef_name, parsed_members, hfile)


def edit_structured_param_type(one_param, members_list, hfile):
    """Check if param is struct or union definition, function, array, bitfield
    or there are multiple parameters.

    Structs, unions and functions need additional parsing.
    """
    if '{' in one_param.type_text:
        name = re.search(r'\}([\w\s\*,]+)$', one_param.type_text)
        if name:
            one_param.name = name.group(1).strip()
        type_text = re.sub(r'\}[\w\s*,]*$', '};', one_param.type_text)
        if one_param.type_text.startswith('struct'):
            s = parse_struct(type_text, hfile)
        elif one_param.type_text.startswith('union'):
            s = parse_union(type_text, hfile)
        elif one_param.type_text.startswith('enum'):
            s = parse_enum(type_text, hfile)
        else:
            s = ''
        one_param.type = s
        return
    # Members that looks like: 'int __SOCKADDR(su_);' are usually macros
    # It's invalid member, we try to determine correct member's type and name.
    one_param.type = re.sub(
        r'^([\w\s\*]*?)\s*\w+\((\w+)[\w\s,\*]*\)', r'\1 \2 ', one_param.type_text).strip()
    if one_param.type_text.endswith(')'):
        parse_function_type(one_param)
        return
    elif one_param.type_text.endswith(']'):
        param = one_param.type_text
        p_type, p_name = split_param_to_type_and_name(param[:param.find('[')])
        one_param.name = p_name
        one_param.type = p_type + ' ' + param[param.find('['):]
        return
    elif':' in one_param.type_text:
        one_param.parse_param_size()
        if ',' in one_param.type_text:
            one_param.parse_multiple_variables(members_list)
            return
    elif ',' in one_param.type_text:
        one_param.parse_multiple_variables(members_list)
        return
    p_type, p_name = split_param_to_type_and_name(one_param.type_text)
    one_param.name = p_name
    one_param.type = p_type


def parse_function_type(param):
    parsed_param = None
    if re.search(r'^[\w\s*]+\([\w\s]*\*\s*\w+\s*\)', param.type_text):
        parsed_param = parse_one_param(param.type_text)
    param.name = parsed_param.name if parsed_param else ''
    param.type = parsed_param.type if parsed_param else ''


def split_members(s):
    """Struct members are separated by semicolon. Returns list of members."""
    parts = []
    bracket_level = 0
    current = []
    for c in s:
        if c == ";" and bracket_level == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            if c == "{":
                bracket_level += 1
            elif c == "}":
                bracket_level -= 1
            current.append(c)
    return parts

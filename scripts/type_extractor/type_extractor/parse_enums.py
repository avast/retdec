"""Parses enums in header file.

Expect file content without comments and preprocessor definitions.
"""

import re

from .utils import object_attr_string_repr


class Enum:
    """Representation of enums info."""

    def __init__(self, name='', type_name='',
                 items=None, header=None):
        """Constructs Enum info."""
        self.name = name
        self.type_name = type_name
        self.items = items if items is not None else []
        self.header = header

    @property
    def name_text(self):
        """Returns a enum's name."""
        return object_attr_string_repr(self.name)

    @property
    def type_name_text(self):
        """Returns a textual representation of the typedefed name."""
        return object_attr_string_repr(self.type_name)

    @property
    def items_list(self):
        """Returns list of enum's parameters."""
        return self.items if self.items is not None else []

    @property
    def header_text(self):
        """Returns a textual representation of header file."""
        return object_attr_string_repr(self.header)

    def __repr__(self):
        return '{}({!r}, {!r})'.format(
            self.__class__.__name__, self.name_text, self.items)

    def repr_json(self):
        return self.__dict__

    def __eq__(self, other):
        return (self.name == other.name and
                self.type_name == other.type_name and
                self.items == other.items)

    def __ne__(self, other):
        return not self == other


class EnumItem:
    def __init__(self, name, value):
        """Constructs enum's item info."""
        self.name = name
        self.value = value

    def __repr__(self):
        return '{!r} = {!r}'.format(self.name, self.value)

    def repr_json(self):
        return self.__dict__

    def __eq__(self, other):
        return (self.name == other.name and
                self.value == other.value)

    def __ne__(self, other):
        return not self == other


def get_all_enums(text):
    """Gets all enums from text."""
    return re.findall(
        r'(?:\btypedef)?\s*enum\s*(?:[\w]+)?\s*\{[^{}]+\}[\w\s,\*]*;',
        text
    )


def parse_enum(enum_str, hfile):
    """Returns enum object."""
    found = re.search(
        r'(\btypedef\b)?\s*enum\s*([\w]+)?(?::\s*\w*)?\s*\{(.+)\}([\w\s,\*]*);',
        enum_str
    )
    if not found:
        return Enum()
    name = found.group(2)
    enum_type_name = found.group(4).strip()
    if not found.group(1):
        enum_type_name = ''

    enum_item = found.group(3).strip()
    if not enum_item:
        return Enum(name, enum_type_name, [], hfile)
    if ',' == enum_item[-1]:
        enum_item = enum_item[:-1]
    enum_item = enum_item.split(', ')

    items_list = []
    value = 0
    for item in enum_item:
        if '=' in item:
            explicit_value = re.search(
                r'=\s*([\+\-]?(?:0x[a-fA-F0-9]+|\d+))', item)
            item = re.sub(r'\s*=.*', '', item)
            if explicit_value is not None:
                if 'x' in explicit_value.group(1):
                    value = int(explicit_value.group(1), 16)
                else:
                    value = int(explicit_value.group(1), 10)
                items_list.append(EnumItem(item.strip(), value))
            else:
                items_list.append(EnumItem(item.strip(), 'x'))
        else:
            items_list.append(EnumItem(item.strip(), value))
        value = value + 1
    return Enum(name, enum_type_name, items_list, hfile)

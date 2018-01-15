"""Representation and parsing of function info."""

import re

from .utils import object_attr_string_repr


class FuncInfo:
    """Representation of function info."""

    def __init__(self, decl, name=None, header=None, ret_type=None,
                 params=None, vararg=False, call_conv=None):
        """Constructs function info.

        params == None means that the parameters are unknown.
        """
        assert decl
        self.decl = decl
        self.name = name
        self.header = header
        self.ret_type = ret_type
        self.params = params if params is not None else []
        if vararg:
            self.vararg = vararg
        if call_conv:
            self.call_conv = call_conv

    @property
    def header_text(self):
        """Returns a textual representation of the header."""
        return object_attr_string_repr(self.header)

    @property
    def name_text(self):
        """Returns a textual representation of the func name."""
        return object_attr_string_repr(self.name)

    @property
    def ret_type_text(self):
        """Returns a textual representation of the return type."""
        return object_attr_string_repr(self.ret_type)

    @property
    def params_list(self):
        """Returns a list of function's parameters."""
        return self.params

    @property
    def has_vararg(self):
        """Returns True if function takes variable number of arguments,
        otherwise False.
        """
        return getattr(self, 'vararg', False)

    @property
    def call_convention(self):
        """Returns function's call convention."""
        return getattr(self, 'call_conv', '')

    def __eq__(self, other):
        return (self.decl == other.decl and
                self.header == other.header and
                self.ret_type == other.ret_type and
                self.params == other.params)

    def __ne__(self, other):
        return not self == other

    def __repr__(self):
        return '{}({!r}, {!r}, {!r}, {!r})'.format(
            self.__class__.__name__, self.decl,
            self.header, self.ret_type, self.params)

    def repr_json(self):
        return self.__dict__

    def delete_underscores_in_param_names(self):
        """Removes redundant underscores from parameter names (also in declaration)."""
        for p in self.params:
            if p.name.startswith('_'):
                p.name = p.name.strip('_')
                self.decl = re.sub(r'_+{}\b'.format(re.escape(p.name)),
                                   p.name, self.decl, 1)


def get_declarations(text):
    """Extracts all function declarations from text."""
    return re.findall(r'\s?\w+[\w\s\*]*\s+\w+\([\w\s\*\+-/,.()[\]]*?\)\s*;', text)


def parse_func_declaration(decl):
    """Gets return type and parameters from declaration."""
    decl = edit_decl(decl)
    m = re.search(r'([\w\s\*]+)\s+(\w+)\s*\(', decl)
    name = m.group(2)
    ret, call_convention = split_ret_type_and_call_convention(m.group(1))
    params_str = re.search(r'\((.*)\)', decl).group(1)
    return name, ret.strip(), params_str, call_convention


def edit_decl(decl):
    """Edits declarations for easier parsing.

    Declarations e.g.:
        int fname OF((int x, char c));
        int BZ_API(fname)(int a);
    """
    decl = re.sub(r'(.*?)\b__NTH\((\w*\(.*?\))\);', r'\1\2;', decl)
    decl = re.sub(r'(.+?\s\w+)\b\w+\((\(.*?\))\);', r'\1\2;', decl)
    decl = re.sub(r'(.*?)\b\w+\((\w+)\)\s*\((.*)\);', r'\1 \2(\3);', decl)
    return decl


CALL_CONVENTIONS = {
    'cdecl',
    'stdcall',
    'pascal',
    'fastcall',
    'thiscall',
}


def split_ret_type_and_call_convention(string):
    if not string:
        return "", ""
    ret_and_cc = string.rsplit(' ', 1)
    if len(ret_and_cc) != 2:
        return string, ""

    call_conv = ret_and_cc[1].strip('_').lower()
    if call_conv not in CALL_CONVENTIONS:
        return string, ""
    else:
        return ret_and_cc[0], call_conv

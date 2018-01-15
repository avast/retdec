"""Representation of functions' and structs' parameters."""

import re

from .utils import object_attr_string_repr

ANNOTATIONS = {
    'IN',
    'OPTIONAL',
    'OUT',
    '_In_',
    '_In_opt_',
    '_In_z_',
    '_Inout_',
    '_Inout_opt_',
    '_Out_',
    '_Out_opt_',
    '__in',
    '__in_opt',
    '__inout',
    '__out',
    '__out_opt',
}


class Param:
    """Representation of function parameters."""

    def __init__(self, name=None, type=None, annotation=None):
        """Constructs parameter's info."""
        self.name = name
        self.type = type
        if annotation:
            self.annotation = annotation

    @property
    def name_text(self):
        """Returns a parameter's name."""
        return object_attr_string_repr(self.name)

    @property
    def type_text(self):
        """Returns a textual representation of the parameter's type."""
        return object_attr_string_repr(self.type)

    @property
    def annotations_text(self):
        """Returns parameter's annotations (if any)."""
        return getattr(self, 'annotations', '')

    def __eq__(self, other):
        return (self.name == other.name and
                self.type == other.type)

    def __ne__(self, other):
        return not self == other

    def __repr__(self):
        rep = '{}({!r} {!r})'.format(
            self.__class__.__name__, self.type, self.name)
        if hasattr(self, 'annotations'):
            rep = rep + ' ' + str(self.annotations)
        return rep

    def repr_json(self):
        return self.__dict__

    def parse_annotations(self):
        """Parses annotations from param type to attribute 'annotations'."""
        found_annots = []
        for annot in self.type.split(' '):
            if annot in ANNOTATIONS:
                found_annots.append('_opt_' if annot == 'OPTIONAL' else annot)
                self.type = re.sub(r'\b%s\b' % annot, '', self.type, 1).strip()
        if found_annots:
            self.annotations = ' '.join(found_annots)
            if self.annotations == 'IN OUT' or self.annotations == 'OUT IN':
                self.annotations = '_Inout_'

    def parse_arrays(self):
        """Gets array range from param name to param type.

        In function 'parse_func_parameters' they are part of param name
        """
        array = re.search(r'\[.*\]', self.name)
        self.type = self.type + ' ' + array.group(0)
        self.name = re.sub(r'\[.*\]', '', self.name)

    def parse_param_size(self):
        """Gets size of parameter in bit fields in structs."""
        size = re.search(r'\d+$', self.type)
        if size:
            self.size = size.group(0)
        self.type = self.type[:self.type_text.rfind(':')].strip()

    def parse_multiple_variables(self, members_list):
        """Gets all params from param type, when there are many params declared
        at once, separated by comma. Last one is in param name, saved to
        members_list while parsing.

        Can occur only in structs/union parsing.
        """
        vars_type = re.search(r'([^,]+)\s\w+,', self.type_text)
        if vars_type is not None:
            vars_type = vars_type.group(1).strip()
            self.type += ','
            vars_names = [v[:-1] for v in self.type_text.split() if ',' in v]
            if vars_names:
                self.type = vars_type
                self.name = vars_names[0]
                for var in vars_names[1:]:
                    new_param = Param(var, vars_type)
                    if hasattr(self, 'size'):
                        new_param.size = self.size
                    members_list.append(new_param)


def parse_func_parameters(params_str):
    """Returns list of parameters. One 'void' param is treated as no parameters.

    Expects that params_str is preprocessed by 'filter_whitespaces' func from
    header_text_filters module.
    """
    if params_str == 'void':
        return []
    params = split_params(params_str)
    parsed_params = []
    for p in params:
        one_param = parse_one_param(p)
        if one_param.type_text:
            parsed_params.append(one_param)
    return parsed_params


def parse_one_param(param):
    """Function parameter in function declaration needs additional parsing to
    detect name and type or when it is array, (pointer to) function.
    """
    one_param = Param('', param)
    one_param.parse_annotations()
    param = one_param.type_text + one_param.name_text
    if param.endswith(')'):
        return parse_function_type(param)
    elif param.endswith(']'):
        p_type, p_name = split_param_to_type_and_name(param[:param.find('[')])
        one_param.name = p_name
        one_param.type = p_type + ' ' + param[param.find('['):]
    else:
        p_type, p_name = split_param_to_type_and_name(param)
        one_param.name = p_name
        one_param.type = p_type

    return one_param


C_KWORDS_IN_TYPE = {
    'char', 'bool', '_Bool', 'short', 'int', 'float', 'double', 'long',
    'signed', 'unsigned', 'const', 'restrict', 'volatile',
}


CTYPES_OF_TWO_WORDS = {'struct', 'union', 'enum', }


def split_param_to_type_and_name(param):
    """Returns two strings - parameter type and name."""

    split = param.split(' ')
    if split[-1] in C_KWORDS_IN_TYPE or split[-1].endswith('*') or len(split) < 2:
        return param, ''

    if split[-2] in CTYPES_OF_TWO_WORDS:
        return param, ''

    if len(split) == 2 and split[-2] == 'const':
        return param, ''

    return ' '.join(split[:-1]), split[-1]


def split_params(s):
    """Parameters separated by comma. Returns list of parameters."""
    parts = []
    bracket_level = 0
    current = []
    for c in (s + ','):
        if c == ',' and bracket_level == 0:
            parts.append(''.join(current).strip())
            current = []
        else:
            if c == '(':
                bracket_level += 1
            elif c == ')':
                bracket_level -= 1
            current.append(c)
    return parts


def parse_function_type(func_type):
    """Splits function type (function or pointer to function) declaration
    to type and name and returns it as Param object.
    """
    # T (*f)(...)
    ret_type_and_name = re.search(r'^[\w\s*]+\(\*\s*(\w*)\s*\)\(', func_type)
    if ret_type_and_name:
        fname = ret_type_and_name.group(1)
        func_type = re.sub(r'^([\w\s*]+\(\*)\s*%s\s*(?=\)\()' % fname, r'\1', func_type, 1)
        return Param(fname, func_type)

    # T (call_convention *f)(...)
    # T (call_convention f)(...)
    # T (f)(...)
    ret_type_and_name = re.search(r'^[\w\s*]+\([\s\w]*?\*?\s*(\w*)\s*\)\(', func_type)
    if ret_type_and_name:
        fname = ret_type_and_name.group(1)
        func_type = re.sub(r'^([\w\s*]+\([\w\s]*\*?)\s*%s\s*(?=\)\()' % fname, r'\1', func_type, 1)
        return Param(fname, func_type)

    # T f(...)
    ret_type_and_name = re.search(r'^[\w\s*]+\s(\w+)\s*\(', func_type)
    if ret_type_and_name:
        fname = ret_type_and_name.group(1)
        func_type = re.sub(r'^([\w\s*]+)\s%s\s*(?=\()' % fname, r'\1 ', func_type, 1)
        return Param(fname, func_type)
    return Param('', '')

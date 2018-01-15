"""Types representation for json output."""

import enum
import hashlib
import re

from .common_types import COMMON_TYPES
from .func_info import CALL_CONVENTIONS
from .params_info import parse_func_parameters
from .parse_enums import Enum
from .parse_structs_unions import CompositeType
from .parse_structs_unions import Struct
from .parse_structs_unions import Union


PRIMITIVE_TYPES = {
    '_Bool',
    '__int16',
    '__int16_t',
    '__int32',
    '__int3264',
    '__int32_t',
    '__int64',
    '__int64_t',
    '__int8',
    '__int8_t',
    '__uint16_t',
    '__uint32_t',
    '__uint64_t',
    '__uint8_t',
    'bool',
    'char',
    'double',
    'float',
    'int',
    'int16_t',
    'int32_t',
    'int64_t',
    'int8_t',
    'int_fast16_t',
    'int_fast32_t',
    'int_fast64_t',
    'int_fast8_t',
    'int_least16_t',
    'int_least32_t',
    'int_least64_t',
    'int_least8_t',
    'intmax_t',
    'intptr_t',
    'long',
    'short',
    'signed',
    'uint16_t',
    'uint32_t',
    'uint64_t',
    'uint8_t',
    'uint_fast16_t',
    'uint_fast32_t',
    'uint_fast64_t',
    'uint_fast8_t',
    'uint_least16_t',
    'uint_least32_t',
    'uint_least64_t',
    'uint_least8_t',
    'uintmax_t',
    'uintptr_t',
    'unsigned',
    'void',
}

QUALIFIER_TYPES = {
    'const',
    'restrict',
    'volatile',
}

FP_TYPES = {
    'float',
    'double',
    'long double',
}


class TYPES(enum.Enum):
    ARRAY = 'array'
    ENUM = 'enum'
    FLOATING_POINT = 'floating_point_type'
    FUNCTION = 'function'
    INTEGRAL = 'integral_type'
    POINTER = 'pointer'
    QUALIFIER = 'qualifier'
    STRUCT = 'structure'
    TYPEDEF = 'typedef'
    UNION = 'union'
    VOID = 'void'


class BaseType:
    """Base class implementing methods common for all types."""

    @property
    def type_text(self):
        return str(self.type)

    def repr_json(self):
        return self.__dict__

    def __eq__(self, other):
        return self.type_hash == other.type_hash


class PrimitiveType(BaseType):
    """Representation of primitive data types."""

    def __init__(self, name='', bit_width=None):
        self.type = TYPES.FLOATING_POINT.value if name in FP_TYPES else TYPES.INTEGRAL.value
        self.name = name
        if bit_width:
            self.bit_width = bit_width

    @property
    def type_hash(self):
        return hash_function(self.name)

    def __repr__(self):
        return '{}({!r} {!r})'.format(self.__class__.__name__, self.type, self.name)


class VoidType(BaseType):
    def __init__(self):
        self.type = TYPES.VOID.value

    @property
    def type_hash(self):
        return hash_function(self.type)

    def __repr__(self):
        return '{}'.format(self.__class__.__name__)


class PointerType(BaseType):
    """Representation of pointer types."""

    def __init__(self, pointed_type):
        self.type = TYPES.POINTER.value
        self.pointed_type = pointed_type.type_hash

    @property
    def type_hash(self):
        return hash_function(self.type + self.pointed_type)

    def __repr__(self):
        return '{}({!r})'.format(
            self.__class__.__name__, self.pointed_type)


class TypedefedType(BaseType):
    """Representation of typedefed types."""

    default = 'unknown'

    def __init__(self, name='', typedefed_type=None):
        self.type = TYPES.TYPEDEF.value
        self.name = name
        if typedefed_type is None:
            self.typedefed_type = self.default
        else:
            self.typedefed_type = typedefed_type.type_hash

    @property
    def type_hash(self):
        return hash_function(self.type + self.name)

    @property
    def name_text(self):
        return str(self.name) if self.name is not None else '?'

    @property
    def known_typedefed_type(self):
        return True if type(self.typedefed_type) != str else False

    def __repr__(self):
        return '{}({!r}, {!r})'.format(
            self.__class__.__name__, self.name, self.typedefed_type)


class QualifierType(BaseType):
    """Representation of type qualifiers const/restrict/volatile."""

    def __init__(self, name='', modified_type=None):
        self.type = TYPES.QUALIFIER.value
        self.name = name
        if modified_type is not None:
            self.modified_type = modified_type.type_hash
        else:
            self.modified_type = ''

    @property
    def type_hash(self):
        return hash_function(self.type + self.name + self.modified_type)

    def __repr__(self):
        return '{}({!r} {!r} {!r})'.format(
            self.__class__.__name__, self.type, self.name, self.modified_type)


class StructType(BaseType):
    """Representation of struct types."""

    def __init__(self, name='', members=None):
        self.type = TYPES.STRUCT.value
        self.name = 'struct ' + name
        self.members = members if members is not None else []

    @property
    def type_hash(self):
        return hash_function(self.name)

    @property
    def has_members(self):
        return True if self.members else False

    def __repr__(self):
        return '{}({!r}, {!r})'.format(
            self.__class__.__name__, self.name, self.members)


class UnionType(BaseType):
    """Representation of union types."""

    def __init__(self, name='', members=None):
        self.type = TYPES.UNION.value
        self.name = 'union ' + name
        self.members = members if members is not None else []

    @property
    def type_hash(self):
        return hash_function(self.name)

    @property
    def has_members(self):
        return True if self.members else False

    def __repr__(self):
        return '{}({!r}, {!r})'.format(
            self.__class__.__name__, self.name, self.members)


class FunctionType(BaseType):
    """Representation of functions as parameters."""

    def __init__(self, ret_type, params=None, vararg=None, call_conv=None):
        self.type = TYPES.FUNCTION.value
        self.ret_type = ret_type.type_hash
        self.params = params if params is not None else []
        if vararg:
            self.vararg = True
        if call_conv:
            self.call_conv = call_conv

    @property
    def type_hash(self):
        hash_source = self.type + self.ret_type + str(self.params)
        hash_source += str(getattr(self, 'vararg', ''))
        hash_source += getattr(self, 'call_conv', '')
        return hash_function(hash_source)

    def __repr__(self):
        return '{}({!r}, {!r})'.format(
            self.__class__.__name__, self.ret_type, self.params)


class ArrayType(BaseType):
    """Representation of arrays."""

    def __init__(self, element_type, dimensions=None):
        self.type = TYPES.ARRAY.value
        self.element_type = element_type.type_hash
        self.dimensions = dimensions if dimensions is not None else []

    @property
    def type_hash(self):
        return hash_function(self.type + self.element_type +
                             str(self.dimensions))

    def __repr__(self):
        return '{}({!r}, {!r})'.format(
            self.__class__.__name__, self.element_type, self.dimensions)


class EnumType(BaseType):
    """Representation of enums."""

    def __init__(self, name='', items=None):
        self.type = TYPES.ENUM.value
        self.name = 'enum ' + name
        self.items = items if items is not None else []

    @property
    def type_hash(self):
        if self.name != 'enum ':
            return hash_function(self.name)
        else:
            return hash_function(self.type + str(self.items))

    def __repr__(self):
        return '{}({!r}, {!r})'.format(
            self.__class__.__name__, self.name, self.items)


def hash_function(str):
    """Returns SHA1 hash of string."""
    return hashlib.sha1(str.encode('utf-8')).hexdigest()


def convert_func_types_to_type_for_json(functions, types):
    """Converts parameters and return type of function declaration to json representation."""
    for name, f_info in functions.items():
        t = parse_type_to_type_for_json(f_info.ret_type_text, types)
        if t.type_hash not in types:
            types[t.type_hash] = t
        f_info.ret_type = t.type_hash
        parse_params_to_json_types(f_info.params_list, types)


def parse_params_to_json_types(params, types):
    for param in params:
        t = parse_type_to_type_for_json(param.type_text, types)
        if t.type_hash not in types:
            types[t.type_hash] = t
        param.type = t.type_hash


def convert_structs_to_type_for_json(structs, types):
    """Converts structs to json representation."""
    for key, struct in structs.items():
        parse_struct_to_type_for_json(struct, types)


def convert_unions_to_type_for_json(unions, types):
    """Converts unions to json representation."""
    for key, union in unions.items():
        parse_union_to_type_for_json(union, types)


def convert_enums_to_type_for_json(enums, types):
    """Converts enums to json representation."""
    for e in enums:
        parse_enum_to_type_for_json(e, types)


def convert_typedefs_to_type_for_json(typedefs, types):
    """Converts enum to json representation."""
    for t in typedefs:
        parse_typedef_to_type_for_json(t, types)


def parse_type_to_type_for_json(str, types):
    """Parse one type - function parameter, return type, struct/union member to
    json representation.
    """
    if type(str) is Struct:
        # struct may be nested in struct/union
        t = parse_struct_to_type_for_json(str, types)
        return t

    if type(str) is Union:
        # union may be nested in struct/union
        t = parse_union_to_type_for_json(str, types)
        return t

    if type(str) is Enum:
        # enum may be nested in struct/union
        t = parse_enum_to_type_for_json(str, types)
        return t

    if str == 'void':
        return VoidType()

    if str.endswith(')'):
        t = parse_func_as_param_to_type_for_json(str, types)
        return t
    elif str.endswith(']'):
        t = parse_array_type(str, types)
        return t

    if not str.strip():
        return TypedefedType('')

    str_list = str.split()
    str_len = len(str_list)

    if str_len == 1:
        t = get_primitive_type_or_typedef(str_list)
    elif '*' in str_list[-1]:
        sub_type = parse_type_to_type_for_json((' '.join(str_list)[:-1].strip()), types)
        if sub_type.type_hash not in types:
            types[sub_type.type_hash] = sub_type
        t = PointerType(sub_type)
    else:
        qualifier = type_qualifier_in_type_list(str_list)
        if qualifier is not None:
            t = parse_qualifier_type(str_list, qualifier, types)
        elif 'struct' in str_list:
            t = StructType(str_list[1])  # expect 'struct sname'
        elif 'union' in str_list:
            t = UnionType(str_list[1])
        elif 'enum' in str_list:
            t = EnumType(str_list[1])
        else:
            t = get_primitive_type_or_typedef(str_list)
            for p in range(str.count('*')):
                t = PointerType(t)

    return t


def type_qualifier_in_type_list(type_list):
    """Returns the type qualifier in str list or None if not found."""
    for item in reversed(type_list):
        if item in QUALIFIER_TYPES:
            return item

    return None


def get_primitive_type_or_typedef(splitted_type):
    """If splitted_type contains some primitive types, then returns them.
    Other stuff (pointers!, macros etc.) ignores. Otherwise typedefed type is returned.

    Bit width is set fo types that we know it for sure.
    """
    primitive = []
    for t in splitted_type:
        if t in PRIMITIVE_TYPES:
            if t == 'void':
                return VoidType()
            primitive.append(t)
    if primitive:
        return parse_primitive_type(' '.join(primitive))
    return parse_typedef(splitted_type)


def parse_primitive_type(type_name):
    """Searches bit width in types, where we are sure that it's fixed."""
    bitWidth = re.search(r'^(?:__)?u?int(8|16|32|64)(?:_t)?$', type_name)
    if bitWidth:
        return PrimitiveType(type_name, int(bitWidth.group(1)))
    return PrimitiveType(type_name)


def parse_typedef(splitted_type):
    """Tries to ignore macros around typedef. Unknown typedef is returned otherwise."""
    if len(splitted_type) == 1 and valid_typedef_name(splitted_type[0]):
        return TypedefedType(splitted_type[0])

    for t in splitted_type:
        if t in COMMON_TYPES:
            return TypedefedType(t)
    return TypedefedType('')


def parse_qualifier_type(str, qualifier, types):
    """Qualifier should be one of QUALIFIER_TYPES."""

    if str[-1] == qualifier:
        str = ' '.join(str[:-1])
    else:
        str.remove(qualifier)
        str = ' '.join(str)

    sub_t = parse_type_to_type_for_json(str, types)

    if sub_t.type_hash not in types:
        types[sub_t.type_hash] = sub_t
    return QualifierType(qualifier, sub_t)


def parse_array_type(str, types):
    """Parses array type. Dimensions stores in one list."""
    array_type_and_size = str.split('[', 1)
    element = parse_type_to_type_for_json(array_type_and_size[0].strip(), types)
    if element.type_hash not in types:
        types[element.type_hash] = element
    dimensions = get_array_dimensions(array_type_and_size[-1])
    return ArrayType(element, dimensions)


def get_array_dimensions(dimensions):
    """Returns list of all dimensions."""
    dimensions = re.sub(r'^\[|\]$', '', dimensions).split('][')
    return [int(d) if d.isdigit() else d for d in dimensions]


def parse_struct_to_type_for_json(struct, types):
    """Parses Struct from struct definition, not struct as parameter."""
    return parse_composite_type_to_json_type(struct, types, StructType)


def parse_union_to_type_for_json(union, types):
    """Parses Union from union definition, not union as parameter."""
    return parse_composite_type_to_json_type(union, types, UnionType)


def parse_composite_type_to_json_type(comp_type, types, json_type=StructType):
    """Parse struct or union to json type."""
    parse_composite_type_members_to_json_type(comp_type, types)

    if not comp_type.type_name_text:
        t = json_type(comp_type.name_text, comp_type.members_list)
        types[t.type_hash] = t
    else:
        if comp_type.name_text:
            sub_t = json_type(comp_type.name_text, comp_type.members_list)
        else:  # not best solution for unique typedef union { }x;
            unique_name = re.sub(r'\s*\*\s*|, ', '_', comp_type.type_name_text)
            sub_t = json_type('_TYPEDEF_' + unique_name, comp_type.members_list)
        types[sub_t.type_hash] = sub_t
        t = parse_typedefs_to_json_type(comp_type.type_name_text, sub_t, types)

    return t


def parse_composite_type_members_to_json_type(comp_type, types):
    for attr in comp_type.members_list:
        if isinstance(attr.type, CompositeType) or isinstance(attr.type, Enum):
            check_name_of_nested_composite_type(attr.type, attr.name, comp_type)
        t = parse_type_to_type_for_json(attr.type, types)
        if t.type_hash not in types:
            types[t.type_hash] = t
        attr.type = t.type_hash


def check_name_of_nested_composite_type(type, param_name, parent):
    """Structs in json representation requires unique name, unnamed would be
    overwritten by another unnamed. We want to store them all.
    """
    if not type.name_text:
        if parent.name_text:
            parent_name = parent.name_text
        else:
            parent_name = parent.type_name_text
            parent_name = re.sub(r'\s*\*\s*|, ', '_', parent_name)
        type.name = '_LOCAL_' + parent_name + '_' + param_name


def parse_typedefs_to_json_type(typedefs, json_type, types):
    """Parses all typedefs to already parsed json types, except typedefs to
    functions (use parse_typedef_to_type_for_json).
    """
    typedefs = typedefs.split(', ')
    for typedef in typedefs:
        if '*' in typedef:
            sub_ptr = PointerType(json_type)
            types[sub_ptr.type_hash] = sub_ptr
            t = TypedefedType(typedef[1:].strip(), sub_ptr)
        else:
            t = TypedefedType(typedef, json_type)
        if valid_typedef_name(t.name_text):
            types[t.type_hash] = t
    return t


def parse_func_as_param_to_type_for_json(str, types):
    """Parses function or pointer to function used as parameter/member."""
    ret_type = parse_type_to_type_for_json(str[0: str.find('(')].strip(), types)
    if ret_type.type_hash not in types:
        types[ret_type.type_hash] = ret_type

    func_str = re.sub(r'.*?\(', '(', str, count=1)
    is_pointer = False
    if func_str.startswith('(*)'):
        is_pointer = True
        func_str = func_str[3:]
    call_conv_and_params = re.search(r'^\(\s*(\w*\s*?\*?)\s*\)(\(.*\))', func_str)
    call_conv = None
    if call_conv_and_params:
        func_str = call_conv_and_params.group(2)
        call_conv = call_conv_and_params.group(1)
        if call_conv.endswith('*'):
            is_pointer = True
            call_conv = call_conv[:-1].strip()
        call_conv = call_conv.lower().strip('_')
        if call_conv not in CALL_CONVENTIONS:
            call_conv = None
    func_str = func_str[1:-1].strip()
    is_vararg = False
    if func_str.endswith('...'):
        is_vararg = True
        func_str = func_str[:-3]
    params = parse_func_parameters(func_str)
    parse_params_to_json_types(params, types)

    func_type = FunctionType(ret_type, params, is_vararg, call_conv)

    if is_pointer:
        if func_type.type_hash not in types:
            types[func_type.type_hash] = func_type
        return PointerType(func_type)
    else:
        return func_type


def parse_enum_to_type_for_json(enum, types):
    if enum.name:
        enum_t = EnumType(enum.name, enum.items_list)
    elif enum.type_name:
        enum_t = EnumType('_TYPEDEF_' + enum.type_name, enum.items_list)
    else:
        enum_t = EnumType('', enum.items_list)

    types[enum_t.type_hash] = enum_t
    if not enum.type_name:
        return enum_t

    parse_typedefs_to_json_type(enum.type_name, enum_t, types)
    return enum_t


def parse_typedef_to_type_for_json(typedef, types):
    """Parses one typedefed types."""
    if not valid_typedef_name(typedef.name):
        return

    t = parse_type_to_type_for_json(typedef.type, types)
    if t.type_hash not in types:
        types[t.type_hash] = t

    # typedef.type is type, typedef.name is new Typedefed type
    new_t = TypedefedType(typedef.name, t)
    if new_t.type_hash not in types:
        types[new_t.type_hash] = new_t


def valid_typedef_name(name):
    """Valid typedef name cannot contain spaces. Also ignore names of primitive types."""
    return re.search(r'^[_a-zA-Z]\w*$', name) and name not in PRIMITIVE_TYPES

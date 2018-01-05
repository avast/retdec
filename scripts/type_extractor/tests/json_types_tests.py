"""Units tests for the type_extractor.json_types module."""

import unittest

from type_extractor.func_info import FuncInfo
from type_extractor.json_types import ArrayType
from type_extractor.json_types import EnumType
from type_extractor.json_types import FunctionType
from type_extractor.json_types import PointerType
from type_extractor.json_types import PrimitiveType
from type_extractor.json_types import QualifierType
from type_extractor.json_types import StructType
from type_extractor.json_types import TypedefedType
from type_extractor.json_types import UnionType
from type_extractor.json_types import VoidType
from type_extractor.json_types import convert_enums_to_type_for_json
from type_extractor.json_types import convert_func_types_to_type_for_json
from type_extractor.json_types import convert_structs_to_type_for_json
from type_extractor.json_types import convert_typedefs_to_type_for_json
from type_extractor.json_types import convert_unions_to_type_for_json
from type_extractor.json_types import get_primitive_type_or_typedef
from type_extractor.json_types import parse_enum_to_type_for_json
from type_extractor.json_types import parse_func_as_param_to_type_for_json
from type_extractor.json_types import parse_struct_to_type_for_json
from type_extractor.json_types import parse_type_to_type_for_json
from type_extractor.json_types import parse_typedef_to_type_for_json
from type_extractor.json_types import parse_union_to_type_for_json
from type_extractor.json_types import valid_typedef_name
from type_extractor.params_info import Param
from type_extractor.parse_enums import Enum
from type_extractor.parse_enums import EnumItem
from type_extractor.parse_enums import parse_enum
from type_extractor.parse_structs_unions import Struct
from type_extractor.parse_structs_unions import Union
from type_extractor.parse_structs_unions import parse_struct
from type_extractor.parse_structs_unions import parse_union


class TypesTests(unittest.TestCase):
    def test_type_text_returns_type_as_string(self):
        self.assertEqual(PrimitiveType('int').type_text, 'integral_type')

    def test_repr_json_returns_correct_dict_for_int(self):
        self.assertEqual(
            PrimitiveType('int').repr_json(),
            {'type': 'integral_type', 'name': 'int'}
        )

    def test_primitive_type_correct_string_repr(self):
        self.assertEqual(
            PrimitiveType('int').__repr__(),
            "PrimitiveType('integral_type' 'int')"
        )

    def test_floating_point_type_correct_string_repr(self):
        self.assertEqual(
            PrimitiveType('float').__repr__(),
            "PrimitiveType('floating_point_type' 'float')"
        )

    def test_pointer_type_correct_string_repr(self):
        prim = PrimitiveType('int')

        self.assertEqual(
            PointerType(prim).__repr__(),
            "PointerType('{}')".format(prim.type_hash)
        )

    def test_typedefed_name_text_returns_correct_string(self):
        self.assertEqual(TypedefedType('Tptr').name_text, 'Tptr')

    def test_typedefed_type_correct_string_repr(self):
        self.assertEqual(TypedefedType('Tptr').__repr__(),
                         "TypedefedType('Tptr', 'unknown')")

    def test_constant_type_correct_string_repr(self):
        prim = PrimitiveType('int')

        self.assertEqual(
            QualifierType('const', prim).__repr__(),
            "QualifierType('qualifier' 'const' '{}')".format(prim.type_hash)
        )

    def test_struct_type_correct_string_repr(self):
        self.assertEqual(StructType('File').__repr__(), "StructType('struct File', [])")

    def test_union_type_correct_string_repr(self):
        self.assertEqual(UnionType('File').__repr__(), "UnionType('union File', [])")

    def test_function_type_correct_string_repr(self):
        ptr = PointerType(PrimitiveType('int'))

        self.assertEqual(
            FunctionType(ptr).__repr__(),
            "FunctionType('{}', [])".format(ptr.type_hash)
        )

    def test_array_type_correct_string_repr(self):
        prim = PrimitiveType('int')
        self.assertEqual(
            ArrayType(prim).__repr__(),
            "ArrayType('{}', [])".format(prim.type_hash)
        )

    def test_enum_type_correct_string_repr(self):
        self.assertEqual(EnumType('errors').__repr__(), "EnumType('enum errors', [])")

    def test_void_type_correct_string_repr(self):
        self.assertEqual(VoidType().__repr__(), "VoidType")

    def test_known_typedefed_type_returns_false_if_unknown_is_set(self):
        self.assertFalse(TypedefedType('Tname').known_typedefed_type)

    def test_has_members_returns_true_if_struct_has_some_data(self):
        self.assertTrue(StructType('s', [Param('x',
                        PrimitiveType('int').type_hash)]).has_members)

    def test_has_members_returns_true_if_union_has_some_data(self):
        self.assertTrue(UnionType('s', [Param('x',
                        PrimitiveType('int').type_hash)]).has_members)


class ParseTypesToTypesForJsonTests(unittest.TestCase):
    def test_parsing_empty_string_to_json_types_returns_typedef_to_unknown(self):
        self.assertEqual(
            parse_type_to_type_for_json('', {}),
            TypedefedType('')
        )

    def test_parse_primitive_type_with_some_trash_returns_primitive_type(self):
        self.assertEqual(
            parse_type_to_type_for_json('preprocessor_macro int', {}),
            PrimitiveType('int')
        )

    def test_parse_ptr_to_primitive_type_with_some_trash(self):
        self.assertEqual(
            parse_type_to_type_for_json('int ** MACRO', {}),
            PointerType(PointerType(PrimitiveType('int')))
        )

    def test_unknown_unsigned_type_is_primitive_type_without_unknown_keywords(self):
        self.assertEqual(
            parse_type_to_type_for_json('CONST unsigned int WINAPI', {}),
            PrimitiveType('unsigned int')
        )

    def test_int_is_primitive_type(self):
        self.assertEqual(
            get_primitive_type_or_typedef(['int']),
            PrimitiveType('int')
        )

    def test_type_from_stdint_h_is_primitive_type(self):
        self.assertEqual(
            get_primitive_type_or_typedef(['uint_fast8_t']),
            PrimitiveType('uint_fast8_t')
        )

    def test_int32_type_from_stdint_h_has_bit_width_attribute(self):
        self.assertEqual(
            get_primitive_type_or_typedef(['uint32_t']).bit_width,
            32
        )

    def test_invalid_typedef_name_is_returned_as_typedef_with_empty_name_and_type(self):
        self.assertEqual(
            get_primitive_type_or_typedef(['xx(xx)']),
            TypedefedType('')
        )

    def test_void_is_parsed_as_void_type(self):
        self.assertEqual(
            parse_type_to_type_for_json('void', {}),
            VoidType()
        )

    def test_long_int_is_primitive_type(self):
        self.assertEqual(
            parse_type_to_type_for_json('long int', {}),
            PrimitiveType('long int')
        )

    def test_Bool_is_primitive_type(self):
        self.assertEqual(
            parse_type_to_type_for_json('_Bool', {}),
            PrimitiveType('_Bool')
        )

    def test_long_double_is_primitive_type(self):
        self.assertEqual(
            parse_type_to_type_for_json('long double', {}),
            PrimitiveType('long double')
        )

    def test_char_ptr_is_pointer_type_to_primitive_type(self):
        self.assertEqual(
            parse_type_to_type_for_json('char *', {}),
            PointerType(PrimitiveType('char'))
        )

    def test_ptr_ptr_char_is_pointer_type_to_pointer_type_to_primitive_type(self):
        self.assertEqual(
            parse_type_to_type_for_json('char **', {}),
            PointerType(PointerType(PrimitiveType('char')))
        )

    def test_const_pointer_to_constant_type_of_primitive_type(self):
        self.assertEqual(
            parse_type_to_type_for_json('const char * const', {}),
            QualifierType('const', PointerType(QualifierType('const', PrimitiveType('char'))))
        )

    def test_not_primitve_type_without_modifiers_is_typedefed_type(self):
        self.assertEqual(
            parse_type_to_type_for_json('FILE', {}),
            TypedefedType('FILE')
        )

    def test_const_char_is_constant_type_of_primitive_type(self):
        self.assertEqual(
            parse_type_to_type_for_json('const char', {}),
            QualifierType('const', PrimitiveType('char'))
        )

    def test_restrict_char_is_restrict_type_of_primitive_type(self):
        self.assertEqual(
            parse_type_to_type_for_json('restrict char', {}),
            QualifierType('restrict', PrimitiveType('char'))
        )

    def test_volatile_char_is_volatile_type_of_primitive_type(self):
        self.assertEqual(
            parse_type_to_type_for_json('volatile char', {}),
            QualifierType('volatile', PrimitiveType('char'))
        )

    def test_const_is_constant_qualifier_without_modified_type(self):
        self.assertEqual(
            QualifierType('const').__repr__(),
            "QualifierType('qualifier' 'const' '')"
        )

    def test_char_const_is_constant_type_of_primitive_type(self):
        self.assertEqual(
            parse_type_to_type_for_json('char const', {}),
            QualifierType('const', PrimitiveType('char'))
        )

    def test_unsigned_type_is_primitive_type(self):
        self.assertEqual(
            parse_type_to_type_for_json('unsigned long int', {}),
            PrimitiveType('unsigned long int')
        )

    def test_unsigned_type_is_primitive_type_place_of_unsigned_not_matter(self):
        self.assertEqual(
            parse_type_to_type_for_json('long unsigned int', {}),
            PrimitiveType('long unsigned int')
        )

    def test_signed_is_primitive_type(self):
        self.assertEqual(
            parse_type_to_type_for_json('signed', {}),
            PrimitiveType('signed')
        )

    def test_signed_modifier_with_primitive_type_is_primitive_type(self):
        self.assertEqual(
            parse_type_to_type_for_json('long signed long int', {}),
            PrimitiveType('long signed long int')
        )

    def test_char_const_ptr_is_pointer_type_to_const_type_of_primitive_type(self):
        self.assertEqual(
            parse_type_to_type_for_json('char const *', {}),
            PointerType(QualifierType('const', PrimitiveType('char')))
        )

    def test_more_modifiers_in_one_type_parsed_correctly(self):
        self.assertEqual(
            parse_type_to_type_for_json('volatile char * const', {}),
            QualifierType(
                'const',
                PointerType(QualifierType('volatile', PrimitiveType('char')))
            )
        )

    def test_ptr_to_const_ptr_to_void_is_(self):
        self.assertEqual(
            parse_type_to_type_for_json('void * const *', {}),
            PointerType(QualifierType('const', PointerType(
                        PrimitiveType('void'))))
        )

    def test_struct_in_params_is_struct_type(self):
        self.assertEqual(
            parse_type_to_type_for_json('struct sname', {}),
            StructType('sname')
        )

    def test_union_in_params_is_union_type(self):
        self.assertEqual(
            parse_type_to_type_for_json('union uname', {}),
            UnionType('uname')
        )

    def test_enum_in_params_is_enum_type(self):
        self.assertEqual(
            parse_type_to_type_for_json('enum ename', {}),
            EnumType('ename')
        )

    def test_parse_ptr_to_const_struct(self):
        self.assertEqual(
            parse_type_to_type_for_json('const struct info *', {}),
            PointerType(QualifierType('const', StructType('info')))
        )

    def test_parse_array_one_dimension(self):
        self.assertEqual(
            parse_type_to_type_for_json('int [10]', {}),
            ArrayType(PrimitiveType('int'), [10])
        )

    def test_parse_const_array_one_dimension(self):
        self.assertEqual(
            parse_type_to_type_for_json('const int [10]', {}),
            ArrayType(QualifierType('const', PrimitiveType('int')), [10])
        )

    def test_parse_array_of_structs(self):
        self.assertEqual(
            parse_type_to_type_for_json('struct A [10]', {}),
            ArrayType(StructType('A'), [10])
        )

    def test_parse_ptr_to_const_struct_inversion(self):
        self.assertEqual(
            parse_type_to_type_for_json('struct info const *', {}),
            PointerType(QualifierType('const', StructType('info')))
        )

    def test_parse_array_multi_dimensional(self):
        self.assertEqual(
            parse_type_to_type_for_json('int [10][10][12]', {}),
            ArrayType(PrimitiveType('int'), [10, 10, 12])
        )

    def test_parse_array_dimensions_not_specified(self):
        self.assertEqual(
            parse_type_to_type_for_json('int [][]', {}),
            ArrayType(PrimitiveType('int'), ['', ''])
        )

    def test_parse_array_one_dimension_not_specified(self):
        self.assertEqual(
            parse_type_to_type_for_json('int [][10]', {}),
            ArrayType(PrimitiveType('int'), ['', 10])
        )

    def test_typedef_name_with_space_is_returned_as_unnamed_unknown_typedef(self):
        self.assertEqual(
            parse_type_to_type_for_json('some Macro', {}),
            TypedefedType('')
        )

    def test_parse_array_dimension_set_by_arithmetic_expr(self):
        self.assertEqual(
            parse_type_to_type_for_json('int [10][5 + sizeof(int) - 4 * 3]', {}),
            ArrayType(PrimitiveType('int'), [10, '5 + sizeof(int) - 4 * 3'])
        )

    def test_parse_struct_to_type_for_json(self):
        types = {}
        struct = 'typedef struct xy { int a;};'

        s_info = parse_struct(struct, 'file')
        parse_struct_to_type_for_json(s_info, types)
        st = StructType('xy', [])
        pt = PrimitiveType('int')
        expected = {st.type_hash: st, pt.type_hash: pt}

        self.assertEqual(types, expected)

    def test_parse_typedef_struct_to_type_for_json(self):
        types = {}
        struct = 'typedef struct xy {} type_s;'

        s_info = parse_struct(struct, 'file')
        parse_struct_to_type_for_json(s_info, types)
        st = StructType('xy', [])
        typedef = TypedefedType('type_s', st)
        expected = {st.type_hash: st, typedef.type_hash: typedef}

        self.assertEqual(types, expected)

    def test_parse_typedef_ptr_to_struct_to_type_for_json(self):
        types = {}
        struct = 'typedef struct xy {} *ptr_s;'

        s_info = parse_struct(struct, 'file')
        parse_struct_to_type_for_json(s_info, types)
        st = StructType('xy', [])
        ptr = PointerType(st)
        typedef = TypedefedType('ptr_s', ptr)
        expected = {st.type_hash: st, ptr.type_hash: ptr,
                    typedef.type_hash: typedef}

        self.assertEqual(types, expected)

    def test_parse_typedef_and_ptr_to_struct_to_type_for_json(self):
        types = {}
        struct = 'typedef struct xy {} *ptr_s, typ;'

        s_info = parse_struct(struct, 'file')
        parse_struct_to_type_for_json(s_info, types)
        st = StructType('xy', [])
        ptr = PointerType(st)
        tptr = TypedefedType('ptr_s', ptr)
        typedef = TypedefedType('typ', st)
        expected = {st.type_hash: st, ptr.type_hash: ptr,
                    tptr.type_hash: tptr, typedef.type_hash: typedef}

        self.assertEqual(types, expected)

    def test_parse_typedef_to_struct_without_name_to_type_for_json(self):
        types = {}
        struct = 'typedef struct {} type_s;'

        s_info = parse_struct(struct, 'file')
        parse_struct_to_type_for_json(s_info, types)
        st = StructType('_TYPEDEF_type_s', [])
        typedef = TypedefedType('type_s', st)
        expected = {st.type_hash: st, typedef.type_hash: typedef}

        self.assertEqual(types, expected)

    def test_struct_with_func_ptr_to_type_for_json(self):
        types = {}
        struct = 'struct s{int *(* ptr)();};'

        s_info = parse_struct(struct, 'file')
        parse_struct_to_type_for_json(s_info, types)
        tint = PrimitiveType('int')
        ptrint = PointerType(tint)
        func = FunctionType(ptrint, [])
        func_ptr = PointerType(func)
        st = StructType('s', [func_ptr])
        expected = {tint.type_hash: tint, ptrint.type_hash: ptrint,
                    func.type_hash: func, func_ptr.type_hash: func_ptr,
                    st.type_hash: st}

        self.assertEqual(types, expected)

    def test_parse_union_to_type_for_json(self):
        types = {}
        union = 'union xy { int a;};'

        s_info = parse_union(union, 'file')
        parse_union_to_type_for_json(s_info, types)
        st = UnionType('xy', [])
        pt = PrimitiveType('int')
        expected = {st.type_hash: st, pt.type_hash: pt}

        self.assertEqual(types, expected)

    def test_parse_typedef_union_to_type_for_json(self):
        types = {}
        union = 'typedef union xy {} type_s;'

        s_info = parse_union(union, 'file')
        parse_union_to_type_for_json(s_info, types)
        st = UnionType('xy', [])
        typedef = TypedefedType('type_s', st)
        expected = {st.type_hash: st, typedef.type_hash: typedef}

        self.assertEqual(types, expected)

    def test_parse_typedef_ptr_to_union_to_type_for_json(self):
        types = {}
        union = 'typedef union xy {} *ptr_s;'

        s_info = parse_union(union, 'file')
        parse_union_to_type_for_json(s_info, types)
        st = UnionType('xy', [])
        ptr = PointerType(st)
        typedef = TypedefedType('ptr_s', ptr)
        expected = {st.type_hash: st, ptr.type_hash: ptr,
                    typedef.type_hash: typedef}

        self.assertEqual(types, expected)

    def test_parse_typedef_and_ptr_to_union_to_type_for_json(self):
        types = {}
        union = 'typedef union xy {} *ptr_s, typ;'

        s_info = parse_union(union, 'file')
        parse_union_to_type_for_json(s_info, types)
        st = UnionType('xy', [])
        ptr = PointerType(st)
        tptr = TypedefedType('ptr_s', ptr)
        typedef = TypedefedType('typ', st)
        expected = {st.type_hash: st, ptr.type_hash: ptr,
                    tptr.type_hash: tptr, typedef.type_hash: typedef}

        self.assertEqual(types, expected)

    def test_parse_typedef_to_union_without_name_to_type_for_json(self):
        types = {}
        union = 'typedef union {} type_s;'

        s_info = parse_union(union, 'file')
        parse_union_to_type_for_json(s_info, types)
        st = UnionType('_TYPEDEF_type_s', [])
        typedef = TypedefedType('type_s', st)
        expected = {st.type_hash: st, typedef.type_hash: typedef}

        self.assertEqual(types, expected)

    def test_union_with_func_ptr_to_type_for_json(self):
        types = {}
        union = 'union s{int *(* ptr)();};'

        s_info = parse_union(union, 'file')
        parse_union_to_type_for_json(s_info, types)
        tint = PrimitiveType('int')
        ptrint = PointerType(tint)
        func = FunctionType(ptrint, [])
        func_ptr = PointerType(func)
        st = UnionType('s', [func_ptr])
        expected = {tint.type_hash: tint, ptrint.type_hash: ptrint,
                    func.type_hash: func, func_ptr.type_hash: func_ptr,
                    st.type_hash: st}

        self.assertEqual(types, expected)

    def test_parse_enum_to_type_for_json(self):
        types = {}
        enum = 'enum x{One = 1, Two = 3};'

        enum_info = parse_enum(enum, 'file')
        parse_enum_to_type_for_json(enum_info, types)
        e = EnumType('x', [EnumItem('One', 1), EnumItem('Two', 3)])
        expected = {e.type_hash: e}

        self.assertEqual(types, expected)

    def test_parse_typedefed_enum_to_type_for_json(self):
        types = {}
        enum = 'typedef enum x{One = 1, Two = 3} my_type;'

        enum_info = parse_enum(enum, 'file')
        parse_enum_to_type_for_json(enum_info, types)
        e = EnumType('x', [EnumItem('One', 1), EnumItem('Two', 3)])
        typ = TypedefedType('my_type', e)
        expected = {e.type_hash: e, typ.type_hash: typ}

        self.assertEqual(types, expected)

    def test_parse_typedefed_ptr_to_enum_to_type_for_json(self):
        types = {}
        enum = 'typedef enum x{One = 1, Two = 3} my_type, *ptr;'

        enum_info = parse_enum(enum, 'file')
        parse_enum_to_type_for_json(enum_info, types)
        e = EnumType('x', [EnumItem('One', 1), EnumItem('Two', 3)])
        typ = TypedefedType('my_type', e)
        ptr = PointerType(e)
        tptr = TypedefedType('ptr', ptr)
        expected = {e.type_hash: e, typ.type_hash: typ,
                    tptr.type_hash: tptr, ptr.type_hash: ptr}

        self.assertEqual(types, expected)

    def test_parse_typedefed_enum_without_name(self):
        types = {}
        enum = 'typedef enum{ }e_type;'

        enum_info = parse_enum(enum, 'file')
        parse_enum_to_type_for_json(enum_info, types)
        enum_type = EnumType('_TYPEDEF_' + 'e_type', [])
        tdef = TypedefedType('e_type')
        expected = {enum_type.type_hash: enum_type, tdef.type_hash: tdef}

        self.assertEqual(types, expected)

    def test_enum_without_name_of_typedef_hash_made_of_data(self):
        types = {}
        enum = parse_enum('enum{ one = 1 };', 'file')

        parse_enum_to_type_for_json(enum, types)
        enum = EnumType('', [EnumItem('one', 1)])
        expected = {enum.type_hash: enum}

        self.assertEqual(types, expected)

    def test_parse_ptr_to_function_to_type_for_json(self):
        types = {}
        fptr = 'void (*)(int p1, double)'

        fptr_type = parse_type_to_type_for_json(fptr, types)
        types[fptr_type.type_hash] = fptr_type

        ret_type = PrimitiveType('void')
        p1 = PrimitiveType('int')
        p2 = PrimitiveType('double')
        func_type = FunctionType(
            ret_type, [Param('p1', p1.type_hash), Param('', p2.type_hash)])
        ptr = PointerType(func_type)
        expected = {ret_type.type_hash: ret_type, p1.type_hash: p1,
                    p2.type_hash: p2, func_type.type_hash: func_type,
                    ptr.type_hash: ptr}

        self.assertEqual(types, expected)

    def test_parse_ptr_to_vararg_function_to_type_for_json(self):
        types = {}
        fptr = 'void (*)(int p1, ...)'

        fptr_type = parse_type_to_type_for_json(fptr, types)
        types[fptr_type.type_hash] = fptr_type

        ret_type = PrimitiveType('void')
        p1 = PrimitiveType('int')
        func_type = FunctionType(
            ret_type, [Param('p1', p1.type_hash)], True)
        ptr = PointerType(func_type)
        expected = {ret_type.type_hash: ret_type, p1.type_hash: p1,
                    func_type.type_hash: func_type, ptr.type_hash: ptr}

        self.assertEqual(types, expected)

    def test_parse_ptr_to_function_with_call_conv_to_type_for_json(self):
        types = {}
        fptr = 'void (__cdecl*)(int p1)'

        fptr_type = parse_type_to_type_for_json(fptr, types)
        types[fptr_type.type_hash] = fptr_type

        ret_type = VoidType()
        p1 = PrimitiveType('int')
        func_type = FunctionType(
            ret_type, [Param('p1', p1.type_hash)], False, 'cdecl')
        ptr = PointerType(func_type)
        expected = {ret_type.type_hash: ret_type, p1.type_hash: p1,
                    func_type.type_hash: func_type, ptr.type_hash: ptr}
        self.assertEqual(types, expected)

    def test_parse_function_with_call_conv_to_type_for_json(self):
        types = {}
        fptr = 'void (__cdecl)(int p1)'

        fptr_type = parse_type_to_type_for_json(fptr, types)
        types[fptr_type.type_hash] = fptr_type

        ret_type = VoidType()
        p1 = PrimitiveType('int')
        func_type = FunctionType(
            ret_type, [Param('p1', p1.type_hash)], False, 'cdecl')
        expected = {ret_type.type_hash: ret_type, p1.type_hash: p1,
                    func_type.type_hash: func_type}
        self.assertEqual(types, expected)

    def test_call_conv_is_set_only_when_one_of_CALL_CONVENTIONS(self):
        types = {}
        fptr = 'void (__MYCALL)(int p1)'

        fptr_type = parse_type_to_type_for_json(fptr, types)
        types[fptr_type.type_hash] = fptr_type

        ret_type = VoidType()
        p1 = PrimitiveType('int')
        func_type = FunctionType(
            ret_type, [Param('p1', p1.type_hash)], False)
        expected = {ret_type.type_hash: ret_type, p1.type_hash: p1,
                    func_type.type_hash: func_type}
        self.assertEqual(types, expected)

    def test_parse_ptr_to_function_with_ptr_to_func_as_param(self):
        types = {}
        fptr = 'void (*)(void (*)())'

        fptr_type = parse_type_to_type_for_json(fptr, types)
        types[fptr_type.type_hash] = fptr_type

        ret_type = PrimitiveType('void')
        param = FunctionType(ret_type, [])
        param_ptr = PointerType(param)
        func_type = FunctionType(
            ret_type, [Param('', param_ptr.type_hash)])
        ptr = PointerType(func_type)
        expected = {ret_type.type_hash: ret_type, param.type_hash: param,
                    param_ptr.type_hash: param_ptr, func_type.type_hash: func_type,
                    ptr.type_hash: ptr}

        self.assertEqual(types, expected)

    def test_parse_ptr_to_function_no_params_to_type_for_json(self):
        types = {}
        fptr = 'void * (*)()'

        fptr_type = parse_type_to_type_for_json(fptr, types)
        types[fptr_type.type_hash] = fptr_type
        ret = PrimitiveType('void')
        ret_type = PointerType(ret)
        func_type = FunctionType(ret_type, [])
        ptr = PointerType(func_type)
        expected = {ret_type.type_hash: ret_type, ret.type_hash: ret,
                    func_type.type_hash: func_type, ptr.type_hash: ptr}

        self.assertEqual(types, expected)

    def test_parse_func_as_paramter_to_type_for_json(self):
        func_type = 'int(int a)'
        ret = PrimitiveType('int')
        param = Param('a', ret.type_hash)

        self.assertEqual(parse_func_as_param_to_type_for_json(func_type, {}),
                         FunctionType(ret, [param]))

    def test_parse_nested_structs_to_type_for_json(self):
        struct = 'struct s1{ struct b{ char c; }s2; };'
        types = {}

        struct = parse_struct(struct, 'file')
        parse_struct_to_type_for_json(struct, types)
        prim = PrimitiveType('char')
        s1 = StructType('s1', [])
        s2 = StructType('b', [])
        expected = {prim.type_hash: prim, s1.type_hash: s1, s2.type_hash: s2}

        self.assertEqual(types, expected)

    def test_parse_nested_structs_without_name_to_type_for_json(self):
        struct = 'struct s1{ struct { char c; }s2; };'
        types = {}

        struct = parse_struct(struct, 'file')
        parse_struct_to_type_for_json(struct, types)
        prim = PrimitiveType('char')
        s1 = StructType('s1', [])
        s2 = StructType('_LOCAL_s1_s2', [])
        expected = {prim.type_hash: prim, s1.type_hash: s1, s2.type_hash: s2}

        self.assertEqual(types, expected)

    def test_parse_nested_union_without_name_to_type_for_json(self):
        union = 'union s1{ union { char c; }s2; };'
        types = {}

        union = parse_struct(union, 'file')
        parse_union_to_type_for_json(union, types)
        prim = PrimitiveType('char')
        s1 = UnionType('s1', [])
        s2 = UnionType('_LOCAL_s1_s2', [])
        expected = {prim.type_hash: prim, s1.type_hash: s1, s2.type_hash: s2}

        self.assertEqual(types, expected)

    def test_parse_nested_union_without_name_to_type_for_json_use_typedefed_name(self):
        union = 'typedef union { union { char c; }s2; } Tunion;'
        types = {}

        union = parse_union(union, 'file')
        parse_union_to_type_for_json(union, types)
        prim = PrimitiveType('char')
        s1 = UnionType('_TYPEDEF_Tunion', [])
        s2 = UnionType('_LOCAL_Tunion_s2', [])
        tdef = TypedefedType('Tunion', s1)
        expected = {prim.type_hash: prim, s1.type_hash: s1, s2.type_hash: s2,
                    tdef.type_hash: tdef}

        self.assertEqual(types, expected)

    def test_typedef_to_int_type_for_json(self):
        types = {}
        typedef = Param('tdef', 'int')

        parse_typedef_to_type_for_json(typedef, types)
        t = PrimitiveType('int')
        tdef = TypedefedType('tdef', t)
        expected = {t.type_hash: t, tdef.type_hash: tdef}

        self.assertEqual(types, expected)

    def test_parse_typedef_with_space_in_name_adds_no_type_to_types(self):
        types = {}
        typedef = Param('new_type xxx', 'int')

        parse_typedef_to_type_for_json(typedef, types)

        self.assertEqual(types, {})

    def test_convert_functions_to_json_type(self):
        function = {'f': FuncInfo('int f(char c);', 'f', 'file', 'int',
                    [Param('c', 'char')])}
        convert_func_types_to_type_for_json(function, {})
        p = PrimitiveType('int')
        c = PrimitiveType('char')
        expected = {'f': FuncInfo('int f(char c);', 'f', 'file', p.type_hash,
                    [Param('c', c.type_hash)])}

        self.assertEqual(function, expected)

    def test_convert_union_to_json_type(self):
        union = {'u': Union('u')}
        types = {}

        convert_unions_to_type_for_json(union, types)

        self.assertEqual(types, {UnionType('u').type_hash: UnionType('u')})

    def test_convert_struct_to_type_json_type(self):
        struct = {'s': Struct('s')}
        types = {}

        convert_structs_to_type_for_json(struct, types)

        self.assertEqual(types, {StructType('s').type_hash: StructType('s')})

    def test_convert_enum_to_type_json_type(self):
        enum = [Enum('e')]
        types = {}

        convert_enums_to_type_for_json(enum, types)

        self.assertEqual(types, {EnumType('e').type_hash: EnumType('e')})

    def test_convert_typedef_to_json_type(self):
        tdef = [Param('x', 'int')]
        types = {}

        convert_typedefs_to_type_for_json(tdef, types)
        x = PrimitiveType('int')

        self.assertEqual(
            types,
            {x.type_hash: x, TypedefedType('x', x).type_hash: TypedefedType('x', x)}
        )

    def test_ignore_macros_around_void_type(self):
        self.assertEqual(
            parse_type_to_type_for_json('void MYAPI', {}),
            VoidType()
        )

    def test_ignore_macros_around_common_typedefs(self):
        self.assertEqual(
            parse_type_to_type_for_json('HRESULT MYAPI', {}),
            TypedefedType('HRESULT')
        )

    def test_parse_ptr_to_common_typedef_correctly(self):
        self.assertEqual(
            parse_type_to_type_for_json('BOOL * MYAPI', {}),
            PointerType(TypedefedType('BOOL'))
        )

    def test_parse_enum_inside_struct_to_type_for_json(self):
        struct = 'struct s{ enum e{ X, Y }p; };'
        types = {}

        struct = parse_struct(struct, 'file')
        parse_struct_to_type_for_json(struct, types)
        e = EnumType('e', [EnumItem('X', 0), EnumItem('Y', 1)])
        s = StructType('s', [Param('p', e)])
        expected = {s.type_hash: s, e.type_hash: e}

        self.assertEqual(types, expected)


class ValidTypedefNameTests(unittest.TestCase):
    def test_name_starting_with_underscore_is_valid(self):
        self.assertTrue(valid_typedef_name('_xyz'))

    def test_name_with_space_is_not_valid(self):
        self.assertFalse(valid_typedef_name('macro int'))

    def test_name_starting_with_number_is_not_valid(self):
        self.assertFalse(valid_typedef_name('1xy'))

    def test_name_with_non_alfanumeric_symbol_is_not_valid(self):
        self.assertFalse(valid_typedef_name('xy*'))

    def test_name_of_primitive_type_is_not_valid(self):
        self.assertFalse(valid_typedef_name('uint32_t'))

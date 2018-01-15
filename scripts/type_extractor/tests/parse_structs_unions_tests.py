"""Units tests for the type_extractor.parse_structs_unions module."""

import unittest

from type_extractor.params_info import Param
from type_extractor.parse_structs_unions import Struct
from type_extractor.parse_structs_unions import Union
from type_extractor.parse_structs_unions import get_all_structs
from type_extractor.parse_structs_unions import get_all_unions
from type_extractor.parse_structs_unions import parse_struct
from type_extractor.parse_structs_unions import parse_union


class GetAllStructsTests(unittest.TestCase):
    def test_get_all_structs_from_text_with_no_structs_in_text(self):
        text = 'random text without {structs ;};'
        text, structs = get_all_structs(text)
        self.assertEqual(structs, [])

    def test_get_all_structs_with_simple_data(self):
        text = """ some declarations( int x);
        struct one{ int a; char *x}; struct next{char c, int a[10];};"""
        expected = [
            'struct one{ int a; char *x};', 'struct next{char c, int a[10];};']

        text, structs = get_all_structs(text)

        self.assertEqual(structs, expected)

    def test_get_struct_with_union_inside(self):
        text = 'struct x { int *x; union{ char c[3]; int a}data; };'
        expected = ['struct x { int *x; union{ char c[3]; int a}data; };']

        text, structs = get_all_structs(text)

        self.assertEqual(structs, expected)

    def test_wrong_brackets_count_return_what_is_already_found(self):
        text = 'struct x { int a; }; struct b{{{ int c;};'
        expected = ['struct x { int a; };']

        text, structs = get_all_structs(text)

        self.assertEqual(structs, expected)


class StructTests(unittest.TestCase):
    def setUp(self):
        self.struct = Struct('s', 'sptr', [], 'h.h')

    def test_header_text_returns_correct_header(self):
        self.assertEqual(self.struct.header_text, 'h.h')

    def test_not_equal_method_true_when_structs_differ(self):
        self.assertNotEqual(self.struct, Struct())

    def test_repr_json_returns_correct_dict(self):
        self.assertEqual(
            self.struct.repr_json(),
            {'name': 's', 'type_name': 'sptr', 'members': [], 'header': 'h.h'}
        )

    def test_repr_returns_correct_string(self):
        self.assertEqual(
            self.struct.__repr__(),
            "Struct('s', [])"
        )


class ParseStructTests(unittest.TestCase):
    def test_input_is_not_struct_contains_struct_keyword(self):
        self.assertEqual(
            parse_struct('no struct ( int ax;);', 'file'),
            Struct('', '', [], 'file')
        )

    def test_parse_struct_with_no_data(self):
        self.assertEqual(
            parse_struct('struct a{};', 'file'),
            Struct('a', '', [], 'file')
        )

    def test_parse_struct_with_simple_data(self):
        self.assertEqual(
            parse_struct('struct x { int x; char * data; };', 'file'),
            Struct('x', '', [Param('x', 'int'), Param('data', 'char *')], 'file')
        )

    def test_parse_struct_nested_structs(self):
        self.assertEqual(
            parse_struct('struct a{ struct c{char b;}b; int a; };', 'file'),
            Struct('a', '', [Param('b', Struct('c', '',
                   [Param('b', 'char')])), Param('a', 'int')], 'file')
        )

    def test_parse_struct_nested_union(self):
        self.assertEqual(
            parse_struct('struct a{ union c{char b;}b; int a; };', 'file'),
            Struct('a', '', [Param('b', Union('c', '',
                   [Param('b', 'char')])), Param('a', 'int')], 'file')
        )

    def test_parse_struct_with_typedef_name(self):
        self.assertEqual(
            parse_struct('typedef struct xy{ int a; char c;} newS, *ptr;', 'file'),
            Struct('xy', 'newS, *ptr', [Param('a', 'int'), Param('c', 'char')], 'file')
        )

    def test_parse_typedef_to_struct_without_name(self):
        self.assertEqual(
            parse_struct('typedef struct{ int a;} newS, *ptr;', 'file'),
            Struct('', 'newS, *ptr', [Param('a', 'int')], 'file')
        )

    def test_parse_struct_with_array_in_data(self):
        self.assertEqual(
            parse_struct('typedef struct{ int a[100];} newS, *ptr;', 'file'),
            Struct('', 'newS, *ptr', [Param('a', 'int [100]')], 'file')
        )

    def test_parse_struct_with_bitfields(self):
        s_info = parse_struct('struct s{int a : 1; int b: 3; char c:5;};', 'file')
        s_expect = Struct('s', '', [Param('a', 'int'), Param('b', 'int'),
                          Param('c', 'char')])

        self.assertEqual(s_info, s_expect)
        self.assertEqual(s_info.members_list[0].size, '1')
        self.assertEqual(s_info.members_list[1].size, '3')
        self.assertEqual(s_info.members_list[2].size, '5')

    def test_parse_struct_few_vars_defined_at_once(self):
        self.assertEqual(
            parse_struct('struct s{int a, b, c;};', 'file'),
            Struct('s', '', [Param('a', 'int'),
                   Param('b', 'int'),
                   Param('c', 'int')])
        )

    def test_parse_struct_with_few_vars_defined_at_once_with_bitfield(self):
        s_info = parse_struct('struct s{int a, b : 1;};', 'file')
        s_expect = Struct('s', '', [Param('a', 'int'), Param('b', 'int')])

        self.assertEqual(s_info, s_expect)
        self.assertEqual(s_info.members_list[0].size, '1')
        self.assertEqual(s_info.members_list[1].size, '1')

    def test_parse_struct_with_func_ptr_as_attribute(self):
        self.assertEqual(
            parse_struct('struct s{int *(* ptr)(int);};', 'file'),
            Struct('s', '', [Param('ptr', 'int *(*)(int)')])
        )

    def test_parse_struct_with_func_as_attribute(self):
        self.assertEqual(
            parse_struct('struct s{int * (* func)(int);};', 'file'),
            Struct('s', '', [Param('func', 'int * (*)(int)')])
        )

    def test_wrong_count_of_brackets_returns_what_is_already_parsed(self):
        self.assertEqual(
            parse_struct('struct s{int i; struct a{{{int b;}};', 'file'),
            Struct('s', '', [Param('i', 'int')])
        )

    def test_parameter_name_wrapped_in_macro_is_correctly_recovered(self):
        self.assertEqual(
            parse_struct('struct s{int __MACRO(name); };', 'file'),
            Struct('s', '', [Param('name', 'int')])
        )

    def test_member_wrapped_in_macro_is_recovered_as_type(self):
        self.assertEqual(
            parse_struct('struct s{ __MACRO(maybe_type); };', 'file'),
            Struct('s', '', [Param('', 'maybe_type')])
        )

    def test_name_after_struct_is_param_name_when_missing_typedef_keyword(self):
        self.assertEqual(
            parse_struct('struct s{int i;}param;', 'file'),
            Struct('s', '', [Param('i', 'int')])
        )

    def test_arithmetic_expr_in_array_size(self):
        self.assertEqual(
            parse_struct('struct s{int a[5 + 4 / 2 - sizeof(int)];};', 'file'),
            Struct('s', '', [Param('a', 'int [5 + 4 / 2 - sizeof(int)]')])
        )

    def test_invalid_member_is_returned_as_empty_type(self):
        self.assertEqual(
            parse_struct('struct s{ int x{int}z; };', 'file'),
            Struct('s', '', [Param('z', '')])
        )


class GetAllUnionsTests(unittest.TestCase):
    def test_get_all_unions_from_text_with_no_unions_in_text(self):
        text = 'random text without {unions ;};'
        text, unions = get_all_unions(text)
        self.assertEqual(unions, [])

    def test_get_all_unions_with_simple_data(self):
        text = """ some declarations( int x);
        union one{ int a; char *x}; union next{char c, int a[10];};"""
        expected = [
            'union one{ int a; char *x};', 'union next{char c, int a[10];};']

        text, unions = get_all_unions(text)

        self.assertEqual(unions, expected)


class ParseUnionTests(unittest.TestCase):
    def test_input_is_not_union_contains_struct_keyword(self):
        self.assertEqual(
            parse_union('no struct ( int ax;);', 'file'),
            Union('', '', [], 'file')
        )

    def test_parse_union_with_no_data(self):
        self.assertEqual(
            parse_union('struct a{};', 'file'),
            Union('a', '', [], 'file')
        )

    def test_parse_union_with_simple_data(self):
        self.assertEqual(
            parse_union('struct x { int x; char * data; };', 'file'),
            Union('x', '', [Param('x', 'int'), Param('data', 'char *')], 'file')
        )

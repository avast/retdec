"""Unit tests for the type_extractor.func_info module."""

import unittest

from type_extractor.func_info import FuncInfo
from type_extractor.func_info import get_declarations
from type_extractor.func_info import parse_func_declaration
from type_extractor.func_info import split_ret_type_and_call_convention
from type_extractor.header_text_filters import use_filters
from type_extractor.params_info import Param
from type_extractor.parse_includes import parse_all_functions


class FuncInfoTests(unittest.TestCase):
    def test_header_text_returns_correct_header_file(self):
        f_info = FuncInfo('int f();', header='header.h')
        self.assertEqual(f_info.header_text, 'header.h')

    def test_name_text_returns_function_name(self):
        f_info = FuncInfo('int f();', name='f')
        self.assertEqual(f_info.name_text, 'f')

    def test_ret_type_text_returns_func_return_type(self):
        f_info = FuncInfo('int f();', ret_type='int')
        self.assertEqual(f_info.ret_type_text, 'int')

    def test_params_list_returns_list_of_func_parameters(self):
        f_info = FuncInfo('int f(char c);', params=[Param('c', 'char')])
        self.assertEqual(f_info.params_list, [Param('c', 'char')])

    def test_has_vararg_returns_false_when_func_takes_fix_count_of_arguments(self):
        f_info = FuncInfo('int f(char c);', vararg=False)
        self.assertEqual(f_info.has_vararg, False)

    def test_call_convention_returns_empty_string_when_conv_is_unknown(self):
        f_info = FuncInfo('int f(char c);')
        self.assertEqual(f_info.call_convention, '')

    def test_call_convention_returns_correct_convention(self):
        f_info = FuncInfo('int f(char c);', call_conv='cdecl')
        self.assertEqual(f_info.call_convention, 'cdecl')

    def test_not_equal_method_returns_false_on_different_funcs(self):
        f_info = FuncInfo('int f(char c);', 'f', 'header.h', 'int',
                          [Param('c', 'char')])
        self.assertNotEqual(f_info, FuncInfo('int f();'))

    def test_repr_method_returns_correct_string(self):
        f_info = FuncInfo('int f(char c);', 'f', 'header.h', 'int',
                          [Param('c', 'char')])
        repr = "FuncInfo('int f(char c);', 'header.h', 'int', [Param('char' 'c')])"
        self.assertEqual(f_info.__repr__(), repr)

    def test_repr_json_returns_correct_dict(self):
        f_info = FuncInfo('int f(char c);', 'f', 'header.h', 'int',
                          [Param('c', 'char')])
        self.assertEqual(
            f_info.repr_json(),
            {'decl': 'int f(char c);', 'name': 'f',
             'header': 'header.h', 'ret_type': 'int',
             'params': [Param('c', 'char')]}
        )

    def test_vararg_function_repr_json_returns_correct_dict(self):
        f_info = FuncInfo('int f(char c);', 'f', 'header.h', 'int',
                          [Param('c', 'char')], vararg=True)

        self.assertEqual(
            f_info.repr_json(),
            {'decl': 'int f(char c);', 'name': 'f',
             'header': 'header.h', 'ret_type': 'int',
             'params': [Param('c', 'char')], 'vararg': True}
        )

    def test_remove_underscores_from_param_names_correctly(self):
        f_info = FuncInfo('int f(char *__c, __type _t);', 'f', 'header.h', 'int',
                          [Param('__c', 'char *'), Param('_t', '__type')], vararg=True)
        expected = FuncInfo('int f(char *c, __type t);', 'f', 'header.h', 'int',
                            [Param('c', 'char *'), Param('t', '__type')], vararg=True)

        f_info.delete_underscores_in_param_names()

        self.assertEqual(f_info, expected)


class GetDeclarationsTests(unittest.TestCase):
    def test_get_all_declarations_from_text_corretly(self):
        self.assertEqual(
            get_declarations('type* some_name(par1, with(brackets), ret *ptr, ...);'),
            ['type* some_name(par1, with(brackets), ret *ptr, ...);']
        )


class UseFiltersTests(unittest.TestCase):
    def test_substitute_inline_function_to_function(self):
        self.assertEqual(
            use_filters('int func(int a, char b) { int a...}'),
            'int func(int a, char b); '
        )


class ParseFuncDeclarationTests(unittest.TestCase):
    def test_parse_func_declaration_with_func_as_parameter(self):
        text = 'ret_type* fname(int x, int f(char a, int c), int d)'

        name, ret, params, call_conv = parse_func_declaration(text)

        self.assertEqual(name, 'fname')
        self.assertEqual(ret, 'ret_type*')
        self.assertEqual(params, 'int x, int f(char a, int c), int d')
        self.assertEqual(call_conv, '')

    def test_parse_func_declaration_without_parameters(self):
        text = 'ret fname()'

        name, ret, params, call_conv = parse_func_declaration(text)

        self.assertEqual(name, 'fname')
        self.assertEqual(ret, 'ret')
        self.assertEqual(params, '')
        self.assertEqual(call_conv, '')

    def test_parse_func_declaration_with_struct_return_type_correctly(self):
        text = 'struct s f()'

        name, ret, params, call_conv = parse_func_declaration(text)

        self.assertEqual(name, 'f')
        self.assertEqual(ret, 'struct s')
        self.assertEqual(params, '')
        self.assertEqual(call_conv, '')

    def test_parse_func_declaration_with_varargs(self):
        text = 'ret fname(int x, ...)'

        name, ret, params, call_conv = parse_func_declaration(text)

        self.assertEqual(name, 'fname')
        self.assertEqual(ret, 'ret')
        self.assertEqual(params, 'int x, ...')
        self.assertEqual(call_conv, '')

    def test_parse_all_function_declarations_from_text(self):
        text = 'int f1(char c, ...); char b(int f);'

        funcs = parse_all_functions(text, 'txt', 'f_file')
        f1 = FuncInfo('int f1(char c, ...);', 'f1', 'f_file', 'int',
                      [Param('c', 'char'), Param('vararg', '...')], True)
        f2 = FuncInfo('char b(int f);', 'b', 'f_file', 'char',
                      [Param('f', 'int')], True)

        self.assertEqual(funcs['f1'], f1)
        self.assertEqual(funcs['b'], f2)

    def test_parse_func_declaration_with_cdecl_convention(self):
        text = 'int cdecl fname(int x)'

        name, ret, params, call_conv = parse_func_declaration(text)

        self.assertEqual(name, 'fname')
        self.assertEqual(ret, 'int')
        self.assertEqual(params, 'int x')
        self.assertEqual(call_conv, 'cdecl')

    def test_parse_func_declaration_with_underscored_call_convention(self):
        text = 'int __stdcall fname(int x)'

        name, ret, params, call_conv = parse_func_declaration(text)

        self.assertEqual(name, 'fname')
        self.assertEqual(ret, 'int')
        self.assertEqual(params, 'int x')
        self.assertEqual(call_conv, 'stdcall')

    def test_parse_func_declaration_with_uppercase_call_convention(self):
        text = 'int STDCALL fname(int x)'

        name, ret, params, call_conv = parse_func_declaration(text)

        self.assertEqual(name, 'fname')
        self.assertEqual(ret, 'int')
        self.assertEqual(params, 'int x')
        self.assertEqual(call_conv, 'stdcall')


class SplitRetTypeAndCallConventionTests(unittest.TestCase):
    def test_split_ret_type_and_call_conv_returns_correct_type_and_convention(self):
        self.assertEqual(
            split_ret_type_and_call_convention('struct x __cdecl'),
            ('struct x', 'cdecl')
        )

    def test_split_ret_type_and_call_conv_returns_empty_strings_on_empty_input(self):
        self.assertEqual(split_ret_type_and_call_convention(''), ('', ''))

"""Units tests for the type_extractor.params_info module."""

import unittest

from type_extractor.params_info import Param
from type_extractor.params_info import parse_func_parameters
from type_extractor.params_info import parse_one_param
from type_extractor.params_info import split_param_to_type_and_name


class ParamNoAttributesSetTestReturnValueTests(unittest.TestCase):
    def setUp(self):
        self.param = Param()

    def test_name_text_returns_when_name_not_set(self):
        self.assertEqual(self.param.name_text, '')

    def test_type_text_returns_when_type_not_set(self):
        self.assertEqual(self.param.type_text, '')

    def test_param_has_no_annotations_returns_empty_string(self):
        self.assertEqual(self.param.annotations_text, '')


class ParamWithAttributesTestMethodsReturnValueTests(unittest.TestCase):
    def setUp(self):
        self.param = Param('x', 'void')

    def test_name_text_correct_return(self):
        self.assertEqual(self.param.name_text, 'x')

    def test_type_text_correct_return(self):
        self.assertEqual(self.param.type_text, 'void')

    def test_not_equal_method(self):
        self.assertNotEqual(Param('n', 'int'), Param('x', 'int'))

    def test_repr_method_returns_correct_str_with_annotations(self):
        self.param.type = '_In_ void'
        self.param.parse_annotations()
        self.assertEqual(self.param.__repr__(), "Param('void' 'x') _In_")

    def test_repr_method_returns_correct_string(self):
        self.assertEqual(self.param.__repr__(), "Param('void' 'x')")

    def test_json_repr_returns_correct_dict(self):
        self.assertEqual(self.param.repr_json(), {'name': 'x', 'type': 'void'})


class ParseFunctionParametersTests(unittest.TestCase):
    def test_parse_empty_string_returns_empty_list_of_params(self):
        self.assertEqual(parse_func_parameters(''), [])

    def test_parse_one_void_parameter(self):
        self.assertEqual(
            parse_func_parameters('void x'),
            [Param('x', 'void')]
        )

    def test_parse_multiple_parameters(self):
        param_str = 'void x, unsigned int a, char * c'
        param1 = Param('x', 'void')
        param2 = Param('a', 'unsigned int')
        param3 = Param('c', 'char *')

        self.assertEqual(parse_func_parameters(param_str),
                         [param1, param2, param3])

    def test_parse_function_as_parameter(self):
        self.assertEqual(
            parse_func_parameters('void * func(int a, char b)'),
            [Param('func', 'void * (int a, char b)')]
        )

    def test_parse_ptr_to_function_as_parameter(self):
        self.assertEqual(
            parse_func_parameters('void * (*)(int a, char b)'),
            [Param('', 'void * (*)(int a, char b)')]
        )

    def test_parse_named_ptr_to_function_as_parameter(self):
        self.assertEqual(
            parse_func_parameters('void * (*func)(int a, char b)'),
            [Param('func', 'void * (*)(int a, char b)')]
        )

    def test_parse_named_ptr_to_function_with_call_convention_as_parameter(self):
        self.assertEqual(
            parse_func_parameters('void * (__cdecl*func)(int a, char b)'),
            [Param('func', 'void * (__cdecl*)(int a, char b)')]
        )

    def test_parse__function_with_call_convention_as_parameter(self):
        self.assertEqual(
            parse_func_parameters('void * (__cdecl func)(int a, char b)'),
            [Param('func', 'void * (__cdecl )(int a, char b)')]
        )

    def test_parse_function_with_name_in_brackets(self):
        self.assertEqual(
            parse_func_parameters('void * (func)(int a, char b)'),
            [Param('func', 'void * ()(int a, char b)')]
        )

    def test_parse_ptr_to_func_with_call_conv_does_not_care_if_conv_is_OK(self):
        self.assertEqual(
            parse_func_parameters('void * (__tricky_macro*func)(int a, char b)'),
            [Param('func', 'void * (__tricky_macro*)(int a, char b)')]
        )

    def test_parse_param_with_nested_brackets_in_params(self):
        self.assertEqual(
            parse_func_parameters('void * func(int a, void (*g)(x))'),
            [Param('func', 'void * (int a, void (*g)(x))')]
        )

    def test_invalid_function_parameter_is_ignored(self):
        param_str = 'char c, int f(int x, int y'
        param = Param('c', 'char')

        self.assertEqual(parse_func_parameters(param_str), [param])

    def test_parse_parameters_without_name_just_returns_type(self):
        param_str = 'int, void *, char **, bool'
        param1 = Param('', 'int')
        param2 = Param('', 'void *')
        param3 = Param('', 'char **')
        param4 = Param('', 'bool')

        self.assertEqual(parse_func_parameters(param_str),
                         [param1, param2, param3, param4])

    def test_parse_function_as_parameter_without_param_names_only_types(self):
        param_str = 'char c_2__, int f(int, char)'
        param1 = Param('c_2__', 'char')
        param2 = Param('f', 'int (int, char)')

        self.assertEqual(parse_func_parameters(param_str), [param1, param2])

    def test_parse_parameters_with_multiword_ret_type(self):
        param_str = 'unsigned int i, int f(unsigned int a, char), char c3'
        param1 = Param('i', 'unsigned int')
        param2 = Param('f', 'int (unsigned int a, char)')
        param3 = Param('c3', 'char')

        self.assertEqual(parse_func_parameters(param_str),
                         [param1, param2, param3])

    def test_parse_parameters_with_in_annotations(self):
        param_str = '_In_ char c_2__, _In_opt_ int f'
        param1 = Param('c_2__', '_In_ char')
        param2 = Param('f', '_In_opt_ int')

        param1.parse_annotations()
        param2.parse_annotations()

        self.assertEqual(parse_func_parameters(param_str), [param1, param2])

    def test_parse_parameters_with_out_annotations(self):
        param_str = '_Inout_ char c_2__, _Out_ int f, _Out_opt_ int x'
        param1 = Param('c_2__', '_Out_ char')
        param2 = Param('f', '_Out_ int')
        param3 = Param('x', '_Out_ int')

        param1.parse_annotations()
        param2.parse_annotations()
        param3.parse_annotations()

        self.assertEqual(parse_func_parameters(param_str),
                         [param1, param2, param3])

    def test_parse__in_annotation(self):
        param_str = '__in int f'
        param = Param('f', '__in int')

        param.parse_annotations()

        self.assertEqual(parse_func_parameters(param_str), [param])

    def test_parse_parameters_with_array(self):
        param_str = 'int x[5], char c'
        param1 = Param('x', 'int [5]')
        param2 = Param('c', 'char')

        self.assertEqual(parse_func_parameters(param_str), [param1, param2])

    def test_parse_parameters_with_array_with_arithmetic_expr(self):
        param_str = 'int x[5 - 4/2 + sizeof(int)], char c'
        param1 = Param('x', 'int [5 - 4/2 + sizeof(int)]')
        param2 = Param('c', 'char')

        self.assertEqual(parse_func_parameters(param_str), [param1, param2])

    def test_parse_parameters_with_two_dimensional_array(self):
        param_str = 'int x[5][10], char c'
        param1 = Param('x', 'int [5][10]')
        param2 = Param('c', 'char')

        self.assertEqual(parse_func_parameters(param_str), [param1, param2])

    def test_parse_annotations_correctly(self):
        param_str = '_In_ int a, _Inout_ int b, _Out_opt_ int c'
        param1 = Param('a', 'int', 'in')
        param2 = Param('b', 'int', 'inout')
        param3 = Param('c', 'int', 'out_opt')

        self.assertEqual(parse_func_parameters(param_str), [param1, param2, param3])

    def test_parse_two_annotations_correctly(self):
        param_str = 'IN OUT int a'

        self.assertEqual(
            parse_func_parameters(param_str)[0].annotations_text,
            '_Inout_'
        )

    def test_parse_annotations_does_not_affect_type(self):
        self.assertEqual(
            parse_func_parameters('IN TYPE_INFO i'),
            [Param('i', 'TYPE_INFO')]
        )

    def test_parse_one_param_returns_empty_param_for_function_param_without_ret_type(self):
        self.assertEqual(parse_one_param('f(int, char)'), Param('', ''))


class SplitParametersWithoutIdentifierToTypeAndNameTests(unittest.TestCase):
    def test_split_const_int_correctly(self):
        self.assertEqual(split_param_to_type_and_name('const int'), ('const int', ''))

    def test_split_const_to_typedefed_type_MY_INT_correctly(self):
        self.assertEqual(split_param_to_type_and_name('const MY_INT'),
                         ('const MY_INT', ''))

    def test_split_char_const_correctly(self):
        self.assertEqual(split_param_to_type_and_name('char const'), ('char const', ''))

    def test_split_unsigned_int_correctly(self):
        self.assertEqual(split_param_to_type_and_name('unsigned int'), ('unsigned int', ''))

    def test_split_long_correctly(self):
        self.assertEqual(split_param_to_type_and_name('long'), ('long', ''))

    def test_split_empty_string_correctly_without_error(self):
        self.assertEqual(split_param_to_type_and_name(''), ('', ''))

    def test_split_pointer_to_int_correctly(self):
        self.assertEqual(split_param_to_type_and_name('int **'), ('int **', ''))

    def test_split_const_pointer_correctly(self):
        self.assertEqual(split_param_to_type_and_name('int * const'), ('int * const', ''))

    def test_split_struct_type_correctly(self):
        self.assertEqual(split_param_to_type_and_name('struct s'), ('struct s', ''))

    def test_parse_array_type_correctly(self):
        self.assertEqual(parse_one_param('int[10]'), Param('', 'int [10]'))

    def test_parse_pointer_to_func_correctly(self):
        self.assertEqual(parse_one_param('int(*)(int a)'), Param('', 'int(*)(int a)'))

    def test_parse_unnamed_param_with_annotation_correctly(self):
        self.assertEqual(parse_one_param('_Out_ LPCSTR'), Param('', 'LPCSTR'))


class SplitParameterWithIdentifierToTypeAndNameTests(unittest.TestCase):
    def test_split_const_int_correctly(self):
        self.assertEqual(split_param_to_type_and_name('const int Tname'),
                         ('const int', 'Tname'))

    def test_split_int_const_correctly(self):
        self.assertEqual(split_param_to_type_and_name('int const Tname'),
                         ('int const', 'Tname'))

    def test_split_struct_correctly(self):
        self.assertEqual(split_param_to_type_and_name('struct s Tname'),
                         ('struct s', 'Tname'))

    def test_split_ptr_to_int_correctly(self):
        self.assertEqual(split_param_to_type_and_name('int ** Tname'),
                         ('int **', 'Tname'))

    def test_parse_array_type_correctly(self):
        self.assertEqual(parse_one_param('int a[10]'), Param('a', 'int [10]'))

    def test_parse_named_pointer_to_func_correctly(self):
        self.assertEqual(parse_one_param('int(* f)(int a)'), Param('f', 'int(*)(int a)'))

    def test_parse_func_as_param_correctly(self):
        self.assertEqual(parse_one_param('int f(int a)'), Param('f', 'int (int a)'))

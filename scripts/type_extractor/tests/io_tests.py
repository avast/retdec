"""Units tests for the type_extractor.io module."""

import unittest

from type_extractor.io import JSONHandler
from type_extractor.io import get_output_format_options
from type_extractor.io import str_types_sub
from type_extractor.io import types_functions_to_json
from type_extractor.io import types_sub


class TypesFunctionsToJSONTests(unittest.TestCase):
    def test_create_json_string_from_types_functions(self):
        json = types_functions_to_json({'primitive type': 'int'},
                                       {'f': 'f(int i);'})

        self.assertEqual(
            json,
            {'functions': {'f': 'f(int i);'}, 'types': {'primitive type': 'int'}}
        )


class JSONHandlerTests(unittest.TestCase):
    def test_class_has_repr_json_method(self):
        class A:
            def __init__(self):
                self.x = 10

            def repr_json(self):
                return self.__dict__
        a = A()

        self.assertEqual(JSONHandler(a), {'x': 10})

    def test_class_has_not_repr_json_method(self):
        class A:
            def __init__(self):
                self.x = 10
        a = A()

        self.assertRaises(TypeError, JSONHandler, a)


class GetOutputFormatOptionsTests(unittest.TestCase):
    def test_output_format_options(self):
        self.assertEqual(get_output_format_options(), ['txt', 'lti', 'json'])


class TypeSubTests(unittest.TestCase):
    def test_lti_type_substitution_int_for_i32(self):
        self.assertEqual(types_sub('int'), 'i32')

    def test_lti_type_substitution_unknown_type_without_change(self):
        self.assertEqual(types_sub('size_t128'), 'size_t128')


class StrTypesSubTests(unittest.TestCase):
    def test_lti_test_long_type_substitution(self):
        self.assertEqual(str_types_sub('long int', 'x'), 'i64')

    def test_lti_test_array_type_substitution(self):
        self.assertEqual(str_types_sub('int [10]', 'x'), '[10 x i32]')

    def test_lti_test_array_type_unknown_dimension_substitution(self):
        self.assertEqual(str_types_sub('int []', 'x'), 'int []')

    def test_lti_test_pointer_type_substitution(self):
        self.assertEqual(str_types_sub('int *', 'x'), 'i32*')

    def test_lti_test_pointer_to_unknown_type_substitution(self):
        self.assertEqual(str_types_sub('new_type*', 'x'), 'new_type*')

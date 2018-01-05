"""Units tests for the type_extractor.parse_enums module."""

import unittest

from type_extractor.parse_enums import Enum
from type_extractor.parse_enums import EnumItem
from type_extractor.parse_enums import get_all_enums
from type_extractor.parse_enums import parse_enum


class GetAllEnumsTests(unittest.TestCase):
    def test_get_all_enums(self):
        text = """enum x {ONE, TWO}; typedef enum y{THREE = 2}type;
               typedef enum z {FIVE, FOUR = 0x12}*ptr;"""
        expected = ['enum x {ONE, TWO};',
                    'typedef enum y{THREE = 2}type;',
                    'typedef enum z {FIVE, FOUR = 0x12}*ptr;']

        enums = get_all_enums(text)

        self.assertEqual(enums, expected)


class EnumTests(unittest.TestCase):
    def setUp(self):
        self.enum = Enum('errors', 't', [EnumItem('x', 1)], 'header.h')

    def test_name_text_returns_correct_name(self):
        self.assertEqual(self.enum.name_text, 'errors')

    def test_type_name_text_returns_correct_typedefed_name(self):
        self.assertEqual(self.enum.type_name_text, 't')

    def test_header_text_returns_correct_header(self):
        self.assertEqual(self.enum.header_text, 'header.h')

    def test_repr_returns_correct_enum_representation(self):
        self.assertEqual(
            self.enum.__repr__(),
            "Enum('errors', ['x' = 1])"
        )

    def test_enum_repr_json_returns_correct_dict(self):
        self.assertEqual(
            Enum('errors', 't', []).repr_json(),
            {'name': 'errors', 'type_name': 't', 'header': None,
             'items': []}
        )

    def test_not_equal_returns_false_for_two_different_enums(self):
        self.assertNotEqual(self.enum, Enum())

    def test_enum_data_not_eq_returns_true_on_different_data(self):
        self.assertNotEqual(EnumItem('x', '1'), EnumItem('y', '1'))

    def test_enum_data_repr_json_returns_correct_dict(self):
        self.assertEqual(
            self.enum.items_list[0].repr_json(),
            {'name': 'x', 'value': 1}
        )


class ParseEnumTests(unittest.TestCase):
    def test_parse_enum_to_enum_object(self):
        enum = 'enum errors {Eone = -1, Etwo, Ethree = 4};'
        items = [EnumItem('Eone', -1), EnumItem('Etwo', 0),
                 EnumItem('Ethree', 4)]

        parsed = parse_enum(enum, 'file')
        expected = Enum('errors', '', items, 'file')

        self.assertEqual(parsed, expected)

    def test_parse_enum_with_hexa_values(self):
        enum = 'enum errors {Eone = 0x1, Ethree = 0xf};'
        items = [EnumItem('Eone', 0x1), EnumItem('Ethree', 0xf)]

        parsed = parse_enum(enum, 'file')
        expected = Enum('errors', '', items, 'file')

        self.assertEqual(parsed, expected)

    def test_parse_typedefed_enum(self):
        enum = 'typedef enum errors {Eone = 1, Etwo,}My_errors;'
        items = [EnumItem('Eone', 1), EnumItem('Etwo', 2)]

        parsed = parse_enum(enum, 'file')
        expected = Enum('errors', 'My_errors', items, 'file')

        self.assertEqual(parsed, expected)

    def test_parse_enum_not_typedefed_some_variable(self):
        enum = 'enum errors {e = 1, r, t = -1} my_enum;'
        items = [EnumItem('e', 1), EnumItem('r', 2),
                 EnumItem('t', -1)]

        parsed = parse_enum(enum, 'file')
        expected = Enum('errors', '', items, 'file')

        self.assertEqual(parsed, expected)

    def test_parse_enum_with_equation_as_value(self):
        enum = 'enum errors {e = (10-sizeof(int), r} my_enum;'
        items = [EnumItem('e', 'x'), EnumItem('r', 1)]

        parsed = parse_enum(enum, 'file')
        expected = Enum('errors', '', items, 'file')

        self.assertEqual(parsed, expected)

    def test_parse_enum_non_interger_value(self):
        enum = 'enum errors {Eone = SOME_DEFINED_VALUE, Ethree};'
        items = [EnumItem('Eone', 'x'), EnumItem('Ethree', 1)]

        parsed = parse_enum(enum, 'file')
        expected = Enum('errors', '', items, 'file')

        self.assertEqual(parsed, expected)

    def test_parse_enum_with_no_attributes_returns_obj_with_empty_list(self):
        self.assertEqual(
            parse_enum('enum x{  };', 'file'),
            Enum('x', '', [], 'file')
        )

    def test_parse_enum_returns_empty_enum_on_ivalid_input(self):
        self.assertEqual(
            parse_enum('xx', ''),
            Enum()
        )

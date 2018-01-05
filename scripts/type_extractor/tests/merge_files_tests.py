"""Unit tests for the merge_files module."""

import json
import unittest

from type_extractor.merge_files import choose_one_type
from type_extractor.merge_files import merge_functions
from type_extractor.merge_files import merge_types


class ChooseOneTypeTests(unittest.TestCase):
    def test_choose_new_struct_with_members(self):
        struct1 = {'type': 'structure', 'members': []}
        struct2 = {'type': 'structure', 'members': [('int', 'x')]}

        self.assertEqual(choose_one_type(struct1, struct2, {}), struct2)

    def test_choose_existing_struct_with_members(self):
        struct1 = {'type': 'structure', 'members': [('int', 'x')]}
        struct2 = {'type': 'structure', 'members': []}

        self.assertEqual(choose_one_type(struct1, struct2, {}), struct1)

    def test_choose_new_union_with_members(self):
        struct1 = {'type': 'union', 'members': []}
        struct2 = {'type': 'union', 'members': [('int', 'x')]}

        self.assertEqual(choose_one_type(struct1, struct2, {}), struct2)

    def test_choose_existing_union_with_members(self):
        struct1 = {'type': 'union', 'members': [('int', 'x')]}
        struct2 = {'type': 'union', 'members': []}

        self.assertEqual(choose_one_type(struct1, struct2, {}), struct1)

    def test_choose_existing_typedef_with_known_typedefed_type(self):
        t1 = {'type': 'typedef', 'typedefed_type': 'struct s'}
        t2 = {'type': 'typedef', 'typedefed_type': 'unknown'}

        self.assertEqual(choose_one_type(t1, t2, {}), t1)

    def test_choose_new_typedef_when_existing_is_unknown(self):
        t1 = {'type': 'typedef', 'typedefed_type': 'unknown'}
        t2 = {'type': 'typedef', 'typedefed_type': 'struct s'}

        self.assertEqual(choose_one_type(t1, t2, {}), t2)

    def test_choose_one_type_when_they_are_same(self):
        t1 = {'type': 'int'}
        t2 = {'type': 'int'}

        self.assertEqual(choose_one_type(t1, t2, {}), t1)


class MergeFunctionsTests(unittest.TestCase):
    def test_merge_functions_chooses_first_function(self):
        merged = {'f1': 'int f1(int a);'}
        new = {'f1': 'int f1();', 'f2': 'int f2(void);'}
        expected = {'f1': 'int f1(int a);', 'f2': 'int f2(void);'}

        merge_functions(merged, new)

        self.assertEqual(merged, expected)


class MergeTypesTests(unittest.TestCase):
    def test_merge_types_calls_choose_one_type_for_conflicts(self):
        merged = {'t1': {'type': 'int'}, 't2': 'struct'}
        new = {'t1': {'type': 'int'}, 't3': 'typedefed_type'}
        expected = {'t1': {'type': 'int'}, 't2': 'struct', 't3': 'typedefed_type'}

        merge_types(merged, new)

        self.assertEqual(merged, expected)

    def test_circular_typedefs_created_while_merging_are_broken_to_unknown(self):
        json1_types = json.loads(
            """
            {
                "0ff7d695c742c443b5c3c60175ffb84414ea7bc7": {
                    "name": "A",
                    "type": "typedef",
                    "typedefed_type": "unknown"
                },
                "ac574f36b4e34657059d13210778a209d24cecc0": {
                    "name": "B",
                    "type": "typedef",
                    "typedefed_type": "0ff7d695c742c443b5c3c60175ffb84414ea7bc7"
                }
            }
            """
        )
        json2_types = json.loads(
            """
            {
                "0ff7d695c742c443b5c3c60175ffb84414ea7bc7": {
                    "name": "A",
                    "type": "typedef",
                    "typedefed_type": "ac574f36b4e34657059d13210778a209d24cecc0"
                },
                "ac574f36b4e34657059d13210778a209d24cecc0": {
                    "name": "B",
                    "type": "typedef",
                    "typedefed_type": "unknown"
                }
            }
            """
        )
        merged = {}
        A_index = '0ff7d695c742c443b5c3c60175ffb84414ea7bc7'
        B_index = 'ac574f36b4e34657059d13210778a209d24cecc0'

        merge_types(merged, json1_types)
        merge_types(merged, json2_types)

        self.assertTrue(
            merged[A_index]['typedefed_type'] == 'unknown' or
            merged[B_index]['typedefed_type'] == 'unknown'
        )

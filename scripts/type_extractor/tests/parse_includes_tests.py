"""Units tests for the type_extractor.parse_includes module."""

import unittest

from type_extractor.func_info import FuncInfo
from type_extractor.params_info import Param
from type_extractor.parse_enums import Enum
from type_extractor.parse_enums import EnumItem
from type_extractor.parse_includes import get_types_info_from_text
from type_extractor.parse_includes import parse_all_enums
from type_extractor.parse_includes import parse_all_functions
from type_extractor.parse_includes import parse_typedefs
from type_extractor.parse_includes import remove_unwanted_functions
from type_extractor.parse_structs_unions import Struct
from type_extractor.parse_structs_unions import Union


class ParseTypedefsTests(unittest.TestCase):
    def test_parse_typedef_to_int(self):
        self.assertEqual(parse_typedefs('typedef int MY_INT;'),
                         [Param('MY_INT', 'int')])

    def test_parse_multitypedef_to_int(self):
        self.assertEqual(parse_typedefs('typedef int INT, INT2;'),
                         [Param('INT', 'int'), Param('INT2', 'int')])

    def test_parse_typedef_to_array(self):
        array = Param('Array[10]', 'int')
        array.parse_arrays()

        self.assertEqual(parse_typedefs('typedef int Array[10];'), [array])

    def test_parse_typedef_to_pointer_to_int(self):
        self.assertEqual(parse_typedefs('typedef int * ptr;'),
                         [Param('ptr', 'int *')])

    def test_parse_typedef_to_pointer_to_function(self):
        self.assertEqual(parse_typedefs('typedef void (* fptr)(int);'),
                         [Param('fptr', 'void (*)(int)')])

    def test_parse_two_typedefs_to_function_correctly(self):
        self.assertEqual(
            parse_typedefs('typedef int f(int, char), (* pf)(int, char);'),
            [Param('f', 'int (int, char)'), Param('pf', 'int (*)(int, char)')]
        )

    def test_parse_typedef_to_pointer_with_brackets(self):
        self.assertEqual(parse_typedefs('typedef void (* ptr);'),
                         [Param('ptr', 'void *')])


class ParseAllEnumsTests(unittest.TestCase):
    def test_parse_all_enums_from_text(self):
        enums = 'enum x{a}; enum y{b, c};'
        enums = parse_all_enums(enums, {})
        expected = [Enum('x', '', [EnumItem('a', 0)]),
                    Enum('y', '', [EnumItem('b', 0), EnumItem('c', 1)])]

        self.assertEqual(enums, expected)


class GetTypesInfoFromTextTests(unittest.TestCase):
    def test_get_one_func_and_struct_from_text(self):
        text = 'int f(int a); struct s{int b;};'
        functions, _, structs, _, _ = get_types_info_from_text('file', text, 'txt')

        self.assertEqual(
            functions, {'f': FuncInfo('int f(int a);',
                        'f', 'file', 'int', [Param('a', 'int')], False)}
        )
        self.assertEqual(
            structs,
            {'s': Struct('s', '', [Param('b', 'int')], 'file')}
        )

    def test_get_union_from_text(self):
        text = 'union s{int b;};'
        _, _, _, unions, _ = get_types_info_from_text(
            'file', text, 'txt')

        self.assertEqual(unions,
                         {'s': Union('s', '', [Param('b', 'int')], 'file')})

    def test_get_func_and_typedef_from_text_in_json_type(self):
        text = 'typedef int INT; int f();'
        functions, types, _, _, _ = get_types_info_from_text('file', text, 'json')

        self.assertEqual(
            functions,
            {'f': FuncInfo('int f();', 'f', 'file', 'int', [])}
        )
        self.assertEqual(types, [Param('INT', 'int')])

    def test_get_union_from_text_in_json_type(self):
        text = 'typedef union{}Tu;'
        _, _, _, unions, _ = get_types_info_from_text('file', text, 'json')

        self.assertEqual(unions, {'Tu': Union('', 'Tu', [], 'file')})

    def test_convert_struct_without_param_to_json_type(self):
        text = 'typedef struct {}tname;'
        _, _, structs, _, _ = get_types_info_from_text('file', text, 'json')

        self.assertEqual(structs, {'tname': Struct('', 'tname', [], 'file')})

    def test_convert_enum_to_type_for_json(self):
        text = 'enum e{a};'
        _, _, _, _, enums = get_types_info_from_text('file', text, 'json')

        self.assertEqual(enums, [Enum('e', '', [EnumItem('a', 0)], 'file')])

    def test_unwanted_functions_are_removed(self):
        text = """
            // Wanted functions.
            INT StrCmpA(LPCSTR lpszStr, LPCSTR lpszComp);
            INT StrCmpW(LPCWSTR lpszStr, LPCWSTR lpszComp);

            // Unwanted functions (see is_wanted() for more details).
            INT StrCmp(LPCTSTR lpszStr, LPCTSTR lpszComp);
            Calling VirtualFreeEx without the MEM_RELEASE not address descriptors(VADs);
        """
        functions, _, _, _, _ = get_types_info_from_text('file', text, 'txt')

        self.assertEqual(functions.keys(), {'StrCmpA', 'StrCmpW'})


class ParseAllFunctionsTests(unittest.TestCase):
    def test_one_param_void_means_func_has_no_params(self):
        self.assertEqual(
            parse_all_functions('void f(void);', 'json', 'file'),
            {'f': FuncInfo('void f(void);', 'f', 'file', 'void', [])}
        )

    def test_do_not_parse_declaration_with_wrong_brackets_count(self):
        self.assertEqual(
            parse_all_functions('void f(int a));', 'json', 'file'),
            {}
        )


class FilterUnwantedFunctions(unittest.TestCase):
    def test_returns_empty_dict_when_there_are_no_functions(self):
        self.assertEqual(remove_unwanted_functions({}), {})

    def test_keeps_functions_which_we_want_to_keep(self):
        funcs_to_keep = {
            'f': FuncInfo('int f();', 'f', 'file', 'int', [])
        }

        self.assertEqual(remove_unwanted_functions(funcs_to_keep), funcs_to_keep)

    def test_removes_functions_which_we_want_to_remove(self):
        # See the body of is_wanted() for more details.
        funcs_to_remove = {
            # Generic Windows functions whose arguments or return types are "T"
            # types (e.g. LPCTSTR).
            'TTypeInArg': FuncInfo(
                'INT TTypeInArg(INT a, LPCTSTR b);',
                'TTypeInArg',
                'windows.h',
                'INT',
                [Param('a', 'INT'), Param('b', 'LPCTSTR')]
            ),
            'TTypeInRetType': FuncInfo(
                'TBYTE TTypeInRetType(void);',
                'TTypeInRetType',
                'windows.h',
                'TBYTE'
            ),
        }

        self.assertEqual(remove_unwanted_functions(funcs_to_remove), {})

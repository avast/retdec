"""Units tests for the type_extractor.arg_parser module."""

import unittest
from unittest import mock

from type_extractor.arg_parser import get_arg_parser_for_extract_types
from type_extractor.arg_parser import get_arg_parser_for_merge_jsons
from type_extractor.arg_parser import get_arg_parser_for_optimize_jsons


class ParseArgsTestsBase(unittest.TestCase):
    """A base class for argument-parsing tests."""

    def setUp(self):
        # Redirect stderr output to prevent emission of error messages during
        # tests.
        patcher = mock.patch('sys.stderr')
        self.stderr = patcher.start()
        self.addCleanup(patcher.stop)


class ParseArgsExtractTypesTests(ParseArgsTestsBase):
    """Tests for parsing extract_types.py script arguments."""

    def setUp(self):
        super().setUp()
        self.parser = get_arg_parser_for_extract_types(__doc__)

    def test_logging_is_false_when_not_given(self):
        args = self.parser.parse_args(['path'])
        self.assertEqual(args.enable_logging, False)

    def test_logging_is_true_when_given_in_short_form(self):
        args = self.parser.parse_args(['path', '-l'])
        self.assertEqual(args.enable_logging, True)

    def test_logging_is_true_when_given_in_long_form(self):
        args = self.parser.parse_args(['path', '--enable-logging'])
        self.assertEqual(args.enable_logging, True)

    def test_output_format_is_json_when_not_given(self):
        args = self.parser.parse_args(['path'])
        self.assertEqual(args.format, 'json')

    def test_output_format_is_parsed_correctly_short_format(self):
        args = self.parser.parse_args(['path', '-f', 'txt'])
        self.assertEqual(args.format, 'txt')

    def test_output_format_is_parsed_correctly_long_format(self):
        args = self.parser.parse_args(['path', '--format', 'txt'])
        self.assertEqual(args.format, 'txt')

    def test_output_directory_is_type_extractor_output_when_not_given(self):
        args = self.parser.parse_args(['path'])
        self.assertEqual(args.output, 'type_extractor_output')

    def test_output_is_parsed_correctly_short_form(self):
        args = self.parser.parse_args(['path', '-o', 'my_dir'])
        self.assertEqual(args.output, 'my_dir')

    def test_output_is_parsed_correctly_long_form(self):
        args = self.parser.parse_args(['path', '--output', 'my_dir'])
        self.assertEqual(args.output, 'my_dir')

    def test_json_indent_is_4_when_not_given(self):
        args = self.parser.parse_args(['path'])
        self.assertEqual(args.json_indent, 4)

    def test_json_indent_is_correct_when_given_as_number(self):
        args = self.parser.parse_args(['path', '--json-indent', '5'])
        self.assertEqual(args.json_indent, 5)

    def test_json_indent_is_correct_when_given_as_string(self):
        args = self.parser.parse_args(['path', '--json-indent', '  '])
        self.assertEqual(args.json_indent, '  ')

    def test_json_indent_is_None_when_given_as_empty_string(self):
        args = self.parser.parse_args(['path', '--json-indent', ''])
        self.assertEqual(args.json_indent, None)

    def test_json_indent_is_None_when_given_as_0(self):
        args = self.parser.parse_args(['path', '--json-indent', '0'])
        self.assertEqual(args.json_indent, None)

    def test_input_file_or_dir_is_required(self):
        with self.assertRaises(SystemExit) as exc:
            self.parser.parse_args([])
        self.assertNotEqual(exc.exception.code, 0)

    def test_input_path_to_file_or_dir_parsed_correctly(self):
        args = self.parser.parse_args(['/usr/include/stdio.h'])
        self.assertEqual(args.path, ['/usr/include/stdio.h'])

    def test_accept_more_paths_to_input_files_or_dirs(self):
        args = self.parser.parse_args(['/usr/include/stdio.h', '/usr/include/'])
        self.assertEqual(args.path, ['/usr/include/stdio.h', '/usr/include/'])


class ParseArgsMergeJsonsTests(ParseArgsTestsBase):
    """Tests for merge_jsons.py script arguments."""

    def setUp(self):
        super().setUp()
        self.parser = get_arg_parser_for_merge_jsons(__doc__)

    def test_logging_is_false_when_not_given(self):
        args = self.parser.parse_args(['path'])
        self.assertEqual(args.enable_logging, False)

    def test_logging_is_true_when_given_in_short_form(self):
        args = self.parser.parse_args(['path', '-l'])
        self.assertEqual(args.enable_logging, True)

    def test_logging_is_true_when_given_in_long_form(self):
        args = self.parser.parse_args(['path', '--enable-logging'])
        self.assertEqual(args.enable_logging, True)

    def test_output_file_is_merge_output_json_when_not_given(self):
        args = self.parser.parse_args(['path'])
        self.assertEqual(args.output, 'merge_output.json')

    def test_output_is_parsed_correctly_short_form(self):
        args = self.parser.parse_args(['path', '-o', 'my_dir'])
        self.assertEqual(args.output, 'my_dir')

    def test_output_is_parsed_correctly_long_form(self):
        args = self.parser.parse_args(['path', '--output', 'my_dir'])
        self.assertEqual(args.output, 'my_dir')

    def test_input_file_or_dir_is_required(self):
        with self.assertRaises(SystemExit) as exc:
            self.parser.parse_args([])
        self.assertNotEqual(exc.exception.code, 0)

    def test_input_path_to_file_is_parsed_correctly(self):
        args = self.parser.parse_args(['output/stdio.json'])
        self.assertEqual(args.path, ['output/stdio.json'])

    def test_accept_more_paths_to_input_files_dirs(self):
        args = self.parser.parse_args(['output/stdio.json', 'json_files/'])
        self.assertEqual(args.path, ['output/stdio.json', 'json_files/'])


class ParseArgsOptimizeJsonTests(ParseArgsTestsBase):
    """Tests for optimize_jsons.py script arguments."""

    def setUp(self):
        super().setUp()
        self.parser = get_arg_parser_for_optimize_jsons(__doc__)

    def test_input_file_or_dir_is_required(self):
        with self.assertRaises(SystemExit) as exc:
            self.parser.parse_args([])
        self.assertNotEqual(exc.exception.code, 0)

    def test_input_path_to_file_is_parsed_correctly(self):
        args = self.parser.parse_args(['in/stdio.json'])
        self.assertEqual(args.path, ['in/stdio.json'])

    def test_accept_more_paths_to_input_files_dirs(self):
        args = self.parser.parse_args(['in/stdio.json', 'json_files/'])
        self.assertEqual(args.path, ['in/stdio.json', 'json_files/'])

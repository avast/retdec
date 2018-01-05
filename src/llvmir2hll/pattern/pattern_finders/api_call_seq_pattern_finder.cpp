/**
* @file src/llvmir2hll/pattern/pattern_finders/api_call_seq_pattern_finder.cpp
* @brief Implementation of APICallSeqPatternFinder.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <map>

#include "retdec/llvmir2hll/analysis/value_analysis.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/obtainer/call_info_obtainer.h"
#include "retdec/llvmir2hll/obtainer/calls_in_module_obtainer.h"
#include "retdec/llvmir2hll/pattern/pattern_finder_factory.h"
#include "retdec/llvmir2hll/pattern/pattern_finders/api_call/api_call_info.h"
#include "retdec/llvmir2hll/pattern/pattern_finders/api_call/api_call_info_seq.h"
#include "retdec/llvmir2hll/pattern/pattern_finders/api_call/api_call_info_seq_parser.h"
#include "retdec/llvmir2hll/pattern/pattern_finders/api_call/api_call_seq_finder.h"
#include "retdec/llvmir2hll/pattern/pattern_finders/api_call/api_call_seq_finders/basic_block_api_call_seq_finder.h"
#include "retdec/llvmir2hll/pattern/pattern_finders/api_call_seq_pattern_finder.h"
#include "retdec/llvmir2hll/pattern/patterns/stmts_pattern.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/utils/ir.h"
#include "retdec/llvm-support/diagnostics.h"

using namespace retdec::llvm_support;

namespace retdec {
namespace llvmir2hll {

REGISTER_AT_FACTORY("APICallSeq", API_CALL_SEQ_PATTERN_FINDER_ID,
	PatternFinderFactory, APICallSeqPatternFinder::create);

namespace {

/// List of patterns.
using Patterns = PatternFinder::Patterns;

/// Mapping of a function name into a sequence of information about API calls
/// that begin with that function.
// Note: Since many patterns may begin with the same function, we use a
// multimap rather than a map.
using APICallInfoSeqMap = std::multimap<std::string, APICallInfoSeq>;

/**
* @brief Parses @a seqTextRepr into APICallInfoSeq and adds it to @a map under
*        key @a funcName.
*/
void parseAndAddAPICallInfoSeqToMap(APICallInfoSeqMap &map,
		const std::string &funcName, const std::string &seqTextRepr) {
	static ShPtr<APICallInfoSeqParser> parser(APICallInfoSeqParser::create());
	Maybe<APICallInfoSeq> seq(parser->parse(seqTextRepr));
	if (seq) {
		map.insert(std::make_pair(funcName, seq.get()));
	} else {
		printErrorMessage(
			"APICallInfoSeqParser failed to parse the following pattern: ",
			seqTextRepr);
	}
}

/**
* @brief Initializes a mapping of function names into a sequence of information
*        about API calls that begin with that function, and returns a constant
*        reference to it.
*
* This functions is supposed to be used to initialize API_CALL_INFO_SEQ_MAP.
*/
const APICallInfoSeqMap &initAPICallInfoSeqMap() {
	static APICallInfoSeqMap map;

	parseAndAddAPICallInfoSeqToMap(map, "_open",
		"X = _open()"
		"_read(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "_open",
		"X = _open()"
		"_write(X)"
	);

	parseAndAddAPICallInfoSeqToMap(map, "_wopen",
		"X = _wopen()"
		"_read(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "_wopen",
		"X = _wopen()"
		"_write(X)"
	);

	parseAndAddAPICallInfoSeqToMap(map, "fopen",
		"X = fopen()"
		"fread(_, _, _, X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "fopen",
		"X = fopen()"
		"fwrite(_, _, _, X)"
	);

	parseAndAddAPICallInfoSeqToMap(map, "fwopen",
		"X = fwopen()"
		"fread(_, _, _, X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "fwopen",
		"X = fwopen()"
		"fwrite(_, _, _, X)"
	);

	parseAndAddAPICallInfoSeqToMap(map, "CreateFile",
		"X = CreateFile()"
		"ReadFile(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CreateFile",
		"X = CreateFile()"
		"WriteFile(X)"
	);

	parseAndAddAPICallInfoSeqToMap(map, "CreateFileA",
		"X = CreateFileA()"
		"ReadFile(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CreateFileA",
		"X = CreateFileA()"
		"WriteFile(X)"
	);

	parseAndAddAPICallInfoSeqToMap(map, "CreateFileW",
		"X = CreateFileW()"
		"ReadFile(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CreateFileW",
		"X = CreateFileW()"
		"WriteFile(X)"
	);

	parseAndAddAPICallInfoSeqToMap(map, "OpenFile",
		"X = OpenFile()"
		"ReadFile(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "OpenFile",
		"X = OpenFile()"
		"WriteFile(X)"
	);

	parseAndAddAPICallInfoSeqToMap(map, "CopyFile",
		"CopyFile(_, X)"
		"_open(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFile",
		"CopyFile(_, X)"
		"_wopen(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFile",
		"CopyFile(_, X)"
		"fopen(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFile",
		"CopyFile(_, X)"
		"fwopen(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFile",
		"CopyFile(_, X)"
		"OpenFile(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFile",
		"CopyFile(_, X)"
		"WinExec(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFile",
		"CopyFile(_, X)"
		"LoadModule(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFile",
		"CopyFile(_, X)"
		"LoadLibrary(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFile",
		"CopyFile(_, X)"
		"LoadLibraryA(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFile",
		"CopyFile(_, X)"
		"LoadLibraryW(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFile",
		"CopyFile(_, X)"
		"CreateProcess(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFile",
		"CopyFile(_, X)"
		"CreateProcessA(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFile",
		"CopyFile(_, X)"
		"CreateProcessW(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFile",
		"CopyFile(_, X)"
		"ShellExecute(_, _, X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFile",
		"CopyFile(_, X)"
		"ShellExecuteA(_, _, X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFile",
		"CopyFile(_, X)"
		"ShellExecuteW(_, _, X)"
	);

	parseAndAddAPICallInfoSeqToMap(map, "CopyFileA",
		"CopyFileA(_, X)"
		"_open(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFileA",
		"CopyFileA(_, X)"
		"_wopen(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFileA",
		"CopyFileA(_, X)"
		"fopen(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFileA",
		"CopyFileA(_, X)"
		"fwopen(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFileA",
		"CopyFileA(_, X)"
		"OpenFile(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFileA",
		"CopyFileA(_, X)"
		"WinExec(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFileA",
		"CopyFileA(_, X)"
		"LoadModule(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFileA",
		"CopyFileA(_, X)"
		"LoadLibrary(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFileA",
		"CopyFileA(_, X)"
		"LoadLibraryA(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFileA",
		"CopyFileA(_, X)"
		"LoadLibraryW(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFileA",
		"CopyFileA(_, X)"
		"CreateProcess(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFileA",
		"CopyFileA(_, X)"
		"CreateProcessA(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFileA",
		"CopyFileA(_, X)"
		"CreateProcessW(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFileA",
		"CopyFileA(_, X)"
		"ShellExecute(_, _, X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFileA",
		"CopyFileA(_, X)"
		"ShellExecuteA(_, _, X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFileA",
		"CopyFileA(_, X)"
		"ShellExecuteW(_, _, X)"
	);

	parseAndAddAPICallInfoSeqToMap(map, "CopyFileW",
		"CopyFileW(_, X)"
		"_open(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFileW",
		"CopyFileW(_, X)"
		"_wopen(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFileW",
		"CopyFileW(_, X)"
		"fopen(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFileW",
		"CopyFileW(_, X)"
		"fwopen(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFileW",
		"CopyFileW(_, X)"
		"OpenFile(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFileW",
		"CopyFileW(_, X)"
		"WinExec(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFileW",
		"CopyFileW(_, X)"
		"LoadModule(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFileW",
		"CopyFileW(_, X)"
		"LoadLibrary(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFileW",
		"CopyFileW(_, X)"
		"LoadLibraryA(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFileW",
		"CopyFileW(_, X)"
		"LoadLibraryW(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFileW",
		"CopyFileW(_, X)"
		"CreateProcess(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFileW",
		"CopyFileW(_, X)"
		"CreateProcessA(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFileW",
		"CopyFileW(_, X)"
		"CreateProcessW(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFileW",
		"CopyFileW(_, X)"
		"ShellExecute(_, _, X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFileW",
		"CopyFileW(_, X)"
		"ShellExecuteA(_, _, X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "CopyFileW",
		"CopyFileW(_, X)"
		"ShellExecuteW(_, _, X)"
	);

	parseAndAddAPICallInfoSeqToMap(map, "MoveFile",
		"MoveFile(_, X)"
		"_open(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFile",
		"MoveFile(_, X)"
		"_wopen(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFile",
		"MoveFile(_, X)"
		"fopen(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFile",
		"MoveFile(_, X)"
		"fwopen(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFile",
		"MoveFile(_, X)"
		"OpenFile(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFile",
		"MoveFile(_, X)"
		"WinExec(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFile",
		"MoveFile(_, X)"
		"LoadModule(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFile",
		"MoveFile(_, X)"
		"LoadLibrary(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFile",
		"MoveFile(_, X)"
		"LoadLibraryA(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFile",
		"MoveFile(_, X)"
		"LoadLibraryW(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFile",
		"MoveFile(_, X)"
		"CreateProcess(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFile",
		"MoveFile(_, X)"
		"CreateProcessA(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFile",
		"MoveFile(_, X)"
		"CreateProcessW(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFile",
		"MoveFile(_, X)"
		"ShellExecute(_, _, X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFile",
		"MoveFile(_, X)"
		"ShellExecuteA(_, _, X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFile",
		"MoveFile(_, X)"
		"ShellExecuteW(_, _, X)"
	);

	parseAndAddAPICallInfoSeqToMap(map, "MoveFileA",
		"MoveFileA(_, X)"
		"_open(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFileA",
		"MoveFileA(_, X)"
		"_wopen(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFileA",
		"MoveFileA(_, X)"
		"fopen(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFileA",
		"MoveFileA(_, X)"
		"fwopen(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFileA",
		"MoveFileA(_, X)"
		"OpenFile(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFileA",
		"MoveFileA(_, X)"
		"WinExec(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFileA",
		"MoveFileA(_, X)"
		"LoadModule(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFileA",
		"MoveFileA(_, X)"
		"LoadLibrary(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFileA",
		"MoveFileA(_, X)"
		"LoadLibraryA(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFileA",
		"MoveFileA(_, X)"
		"LoadLibraryW(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFileA",
		"MoveFileA(_, X)"
		"CreateProcess(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFileA",
		"MoveFileA(_, X)"
		"CreateProcessA(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFileA",
		"MoveFileA(_, X)"
		"CreateProcessW(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFileA",
		"MoveFileA(_, X)"
		"ShellExecute(_, _, X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFileA",
		"MoveFileA(_, X)"
		"ShellExecuteA(_, _, X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFileA",
		"MoveFileA(_, X)"
		"ShellExecuteW(_, _, X)"
	);

	parseAndAddAPICallInfoSeqToMap(map, "MoveFileW",
		"MoveFileW(_, X)"
		"_open(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFileW",
		"MoveFileW(_, X)"
		"_wopen(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFileW",
		"MoveFileW(_, X)"
		"fopen(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFileW",
		"MoveFileW(_, X)"
		"fwopen(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFileW",
		"MoveFileW(_, X)"
		"OpenFile(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFileW",
		"MoveFileW(_, X)"
		"WinExec(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFileW",
		"MoveFileW(_, X)"
		"CreateProcess(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFileW",
		"MoveFileW(_, X)"
		"CreateProcessA(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFileW",
		"MoveFileW(_, X)"
		"CreateProcessW(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFileW",
		"MoveFileW(_, X)"
		"LoadModule(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFileW",
		"MoveFileW(_, X)"
		"LoadLibrary(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFileW",
		"MoveFileW(_, X)"
		"LoadLibraryA(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFileW",
		"MoveFileW(_, X)"
		"LoadLibraryW(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFileW",
		"MoveFileW(_, X)"
		"ShellExecute(_, _, X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFileW",
		"MoveFileW(_, X)"
		"ShellExecuteA(_, _, X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "MoveFileW",
		"MoveFileW(_, X)"
		"ShellExecuteW(_, _, X)"
	);

	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFile",
		"URLDownloadToFile(_, _, X)"
		"_open(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFile",
		"URLDownloadToFile(_, _, X)"
		"_wopen(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFile",
		"URLDownloadToFile(_, _, X)"
		"fopen(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFile",
		"URLDownloadToFile(_, _, X)"
		"fwopen(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFile",
		"URLDownloadToFile(_, _, X)"
		"OpenFile(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFile",
		"URLDownloadToFile(_, _, X)"
		"WinExec(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFile",
		"URLDownloadToFile(_, _, X)"
		"LoadModule(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFile",
		"URLDownloadToFile(_, _, X)"
		"LoadLibrary(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFile",
		"URLDownloadToFile(_, _, X)"
		"LoadLibraryA(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFile",
		"URLDownloadToFile(_, _, X)"
		"LoadLibraryW(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFile",
		"URLDownloadToFile(_, _, X)"
		"CreateProcess(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFile",
		"URLDownloadToFile(_, _, X)"
		"CreateProcessA(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFile",
		"URLDownloadToFile(_, _, X)"
		"CreateProcessW(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFile",
		"URLDownloadToFile(_, _, X)"
		"ShellExecute(_, _, X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFile",
		"URLDownloadToFile(_, _, X)"
		"ShellExecuteA(_, _, X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFile",
		"URLDownloadToFile(_, _, X)"
		"ShellExecuteW(_, _, X)"
	);

	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFileA",
		"URLDownloadToFileA(_, _, X)"
		"_open(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFileA",
		"URLDownloadToFileA(_, _, X)"
		"_wopen(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFileA",
		"URLDownloadToFileA(_, _, X)"
		"fopen(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFileA",
		"URLDownloadToFileA(_, _, X)"
		"fwopen(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFileA",
		"URLDownloadToFileA(_, _, X)"
		"OpenFile(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFileA",
		"URLDownloadToFileA(_, _, X)"
		"WinExec(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFileA",
		"URLDownloadToFileA(_, _, X)"
		"LoadModule(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFileA",
		"URLDownloadToFileA(_, _, X)"
		"LoadLibrary(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFileA",
		"URLDownloadToFileA(_, _, X)"
		"LoadLibraryA(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFileA",
		"URLDownloadToFileA(_, _, X)"
		"LoadLibraryW(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFileA",
		"URLDownloadToFileA(_, _, X)"
		"CreateProcess(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFileA",
		"URLDownloadToFileA(_, _, X)"
		"CreateProcessA(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFileA",
		"URLDownloadToFileA(_, _, X)"
		"CreateProcessW(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFileA",
		"URLDownloadToFileA(_, _, X)"
		"ShellExecute(_, _, X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFileA",
		"URLDownloadToFileA(_, _, X)"
		"ShellExecuteA(_, _, X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFileA",
		"URLDownloadToFileA(_, _, X)"
		"ShellExecuteW(_, _, X)"
	);

	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFileW",
		"URLDownloadToFileW(_, _, X)"
		"_open(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFileW",
		"URLDownloadToFileW(_, _, X)"
		"_wopen(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFileW",
		"URLDownloadToFileW(_, _, X)"
		"fopen(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFileW",
		"URLDownloadToFileW(_, _, X)"
		"fwopen(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFileW",
		"URLDownloadToFileW(_, _, X)"
		"OpenFile(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFileW",
		"URLDownloadToFileW(_, _, X)"
		"WinExec(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFileW",
		"URLDownloadToFileW(_, _, X)"
		"LoadModule(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFileW",
		"URLDownloadToFileW(_, _, X)"
		"LoadLibrary(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFileW",
		"URLDownloadToFileW(_, _, X)"
		"LoadLibraryA(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFileW",
		"URLDownloadToFileW(_, _, X)"
		"LoadLibraryW(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFileW",
		"URLDownloadToFileW(_, _, X)"
		"CreateProcess(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFileW",
		"URLDownloadToFileW(_, _, X)"
		"CreateProcessA(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFileW",
		"URLDownloadToFileW(_, _, X)"
		"CreateProcessW(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFileW",
		"URLDownloadToFileW(_, _, X)"
		"ShellExecute(_, _, X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFileW",
		"URLDownloadToFileW(_, _, X)"
		"ShellExecuteA(_, _, X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToFileW",
		"URLDownloadToFileW(_, _, X)"
		"ShellExecuteW(_, _, X)"
	);

	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFile",
		"URLDownloadToCacheFile(_, _, X)"
		"_open(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFile",
		"URLDownloadToCacheFile(_, _, X)"
		"_wopen(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFile",
		"URLDownloadToCacheFile(_, _, X)"
		"fopen(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFile",
		"URLDownloadToCacheFile(_, _, X)"
		"fwopen(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFile",
		"URLDownloadToCacheFile(_, _, X)"
		"OpenFile(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFile",
		"URLDownloadToCacheFile(_, _, X)"
		"WinExec(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFile",
		"URLDownloadToCacheFile(_, _, X)"
		"LoadModule(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFile",
		"URLDownloadToCacheFile(_, _, X)"
		"LoadLibrary(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFile",
		"URLDownloadToCacheFile(_, _, X)"
		"LoadLibraryA(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFile",
		"URLDownloadToCacheFile(_, _, X)"
		"LoadLibraryW(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFile",
		"URLDownloadToCacheFile(_, _, X)"
		"CreateProcess(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFile",
		"URLDownloadToCacheFile(_, _, X)"
		"CreateProcessA(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFile",
		"URLDownloadToCacheFile(_, _, X)"
		"CreateProcessW(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFile",
		"URLDownloadToCacheFile(_, _, X)"
		"ShellExecute(_, _, X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFile",
		"URLDownloadToCacheFile(_, _, X)"
		"ShellExecuteA(_, _, X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFile",
		"URLDownloadToCacheFile(_, _, X)"
		"ShellExecuteW(_, _, X)"
	);

	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFileA",
		"URLDownloadToCacheFileA(_, _, X)"
		"_open(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFileA",
		"URLDownloadToCacheFileA(_, _, X)"
		"_wopen(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFileA",
		"URLDownloadToCacheFileA(_, _, X)"
		"fopen(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFileA",
		"URLDownloadToCacheFileA(_, _, X)"
		"fwopen(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFileA",
		"URLDownloadToCacheFileA(_, _, X)"
		"OpenFile(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFileA",
		"URLDownloadToCacheFileA(_, _, X)"
		"WinExec(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFileA",
		"URLDownloadToCacheFileA(_, _, X)"
		"LoadModule(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFileA",
		"URLDownloadToCacheFileA(_, _, X)"
		"LoadLibrary(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFileA",
		"URLDownloadToCacheFileA(_, _, X)"
		"LoadLibraryA(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFileA",
		"URLDownloadToCacheFileA(_, _, X)"
		"LoadLibraryW(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFileA",
		"URLDownloadToCacheFileA(_, _, X)"
		"CreateProcess(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFileA",
		"URLDownloadToCacheFileA(_, _, X)"
		"CreateProcessA(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFileA",
		"URLDownloadToCacheFileA(_, _, X)"
		"CreateProcessW(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFileA",
		"URLDownloadToCacheFileA(_, _, X)"
		"ShellExecute(_, _, X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFileA",
		"URLDownloadToCacheFileA(_, _, X)"
		"ShellExecuteA(_, _, X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFileA",
		"URLDownloadToCacheFileA(_, _, X)"
		"ShellExecuteW(_, _, X)"
	);

	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFileW",
		"URLDownloadToCacheFileW(_, _, X)"
		"_open(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFileW",
		"URLDownloadToCacheFileW(_, _, X)"
		"_wopen(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFileW",
		"URLDownloadToCacheFileW(_, _, X)"
		"fopen(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFileW",
		"URLDownloadToCacheFileW(_, _, X)"
		"fwopen(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFileW",
		"URLDownloadToCacheFileW(_, _, X)"
		"OpenFile(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFileW",
		"URLDownloadToCacheFileW(_, _, X)"
		"WinExec(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFileW",
		"URLDownloadToCacheFileW(_, _, X)"
		"LoadModule(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFileW",
		"URLDownloadToCacheFileW(_, _, X)"
		"LoadLibrary(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFileW",
		"URLDownloadToCacheFileW(_, _, X)"
		"LoadLibraryA(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFileW",
		"URLDownloadToCacheFileW(_, _, X)"
		"LoadLibraryW(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFileW",
		"URLDownloadToCacheFileW(_, _, X)"
		"CreateProcess(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFileW",
		"URLDownloadToCacheFileW(_, _, X)"
		"CreateProcessA(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFileW",
		"URLDownloadToCacheFileW(_, _, X)"
		"CreateProcessW(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFileW",
		"URLDownloadToCacheFileW(_, _, X)"
		"ShellExecute(_, _, X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFileW",
		"URLDownloadToCacheFileW(_, _, X)"
		"ShellExecuteA(_, _, X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "URLDownloadToCacheFileW",
		"URLDownloadToCacheFileW(_, _, X)"
		"ShellExecuteW(_, _, X)"
	);

	parseAndAddAPICallInfoSeqToMap(map, "RegOpenKey",
		"RegOpenKey(_, _, X)"
		"RegSetValue(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "RegOpenKey",
		"RegOpenKey(_, _, X)"
		"RegSetValueA(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "RegOpenKey",
		"RegOpenKey(_, _, X)"
		"RegSetValueW(X)"
	);

	parseAndAddAPICallInfoSeqToMap(map, "RegOpenKeyA",
		"RegOpenKeyA(_, _, X)"
		"RegSetValue(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "RegOpenKeyA",
		"RegOpenKeyA(_, _, X)"
		"RegSetValueA(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "RegOpenKeyA",
		"RegOpenKeyA(_, _, X)"
		"RegSetValueW(X)"
	);

	parseAndAddAPICallInfoSeqToMap(map, "RegOpenKeyW",
		"RegOpenKeyW(_, _, X)"
		"RegSetValue(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "RegOpenKeyW",
		"RegOpenKeyW(_, _, X)"
		"RegSetValueA(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "RegOpenKeyW",
		"RegOpenKeyW(_, _, X)"
		"RegSetValueW(X)"
	);

	parseAndAddAPICallInfoSeqToMap(map, "RegOpenKeyEx",
		"RegOpenKeyEx(_, _, _, _, X)"
		"RegSetValueEx(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "RegOpenKeyEx",
		"RegOpenKeyEx(_, _, _, _, X)"
		"RegSetValueExA(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "RegOpenKeyEx",
		"RegOpenKeyEx(_, _, _, _, X)"
		"RegSetValueExW(X)"
	);

	parseAndAddAPICallInfoSeqToMap(map, "RegOpenKeyExA",
		"RegOpenKeyExA(_, _, _, _, X)"
		"RegSetValueEx(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "RegOpenKeyExA",
		"RegOpenKeyExA(_, _, _, _, X)"
		"RegSetValueExA(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "RegOpenKeyExA",
		"RegOpenKeyExA(_, _, _, _, X)"
		"RegSetValueExW(X)"
	);

	parseAndAddAPICallInfoSeqToMap(map, "RegOpenKeyExW",
		"RegOpenKeyExW(_, _, _, _, X)"
		"RegSetValueEx(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "RegOpenKeyExW",
		"RegOpenKeyExW(_, _, _, _, X)"
		"RegSetValueExA(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "RegOpenKeyExW",
		"RegOpenKeyExW(_, _, _, _, X)"
		"RegSetValueExW(X)"
	);

	parseAndAddAPICallInfoSeqToMap(map, "RegCreateKey",
		"RegCreateKey(_, _, X)"
		"RegSetValue(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "RegCreateKey",
		"RegCreateKey(_, _, X)"
		"RegSetValueA(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "RegCreateKey",
		"RegCreateKey(_, _, X)"
		"RegSetValueW(X)"
	);

	parseAndAddAPICallInfoSeqToMap(map, "RegCreateKeyA",
		"RegCreateKeyA(_, _, X)"
		"RegSetValue(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "RegCreateKeyA",
		"RegCreateKeyA(_, _, X)"
		"RegSetValueA(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "RegCreateKeyA",
		"RegCreateKeyA(_, _, X)"
		"RegSetValueW(X)"
	);

	parseAndAddAPICallInfoSeqToMap(map, "RegCreateKeyW",
		"RegCreateKeyW(_, _, X)"
		"RegSetValue(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "RegCreateKeyW",
		"RegCreateKeyW(_, _, X)"
		"RegSetValueA(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "RegCreateKeyW",
		"RegCreateKeyW(_, _, X)"
		"RegSetValueW(X)"
	);

	parseAndAddAPICallInfoSeqToMap(map, "RegCreateKeyEx",
		"RegCreateKeyEx(_, _, _, _, _, _, _, X)"
		"RegSetValueEx(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "RegCreateKeyEx",
		"RegCreateKeyEx(_, _, _, _, _, _, _, X)"
		"RegSetValueExA(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "RegCreateKeyEx",
		"RegCreateKeyEx(_, _, _, _, _, _, _, X)"
		"RegSetValueExW(X)"
	);

	parseAndAddAPICallInfoSeqToMap(map, "RegCreateKeyExA",
		"RegCreateKeyExA(_, _, _, _, _, _, _, X)"
		"RegSetValueEx(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "RegCreateKeyExA",
		"RegCreateKeyExA(_, _, _, _, _, _, _, X)"
		"RegSetValueExA(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "RegCreateKeyExA",
		"RegCreateKeyExA(_, _, _, _, _, _, _, X)"
		"RegSetValueExW(X)"
	);

	parseAndAddAPICallInfoSeqToMap(map, "RegCreateKeyExW",
		"RegCreateKeyExW(_, _, _, _, _, _, _, X)"
		"RegSetValueEx(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "RegCreateKeyExW",
		"RegCreateKeyExW(_, _, _, _, _, _, _, X)"
		"RegSetValueExA(X)"
	);
	parseAndAddAPICallInfoSeqToMap(map, "RegCreateKeyExW",
		"RegCreateKeyExW(_, _, _, _, _, _, _, X)"
		"RegSetValueExW(X)"
	);

	return map;
}

// TODO Move the initialization of API_CALL_INFO_SEQ_MAP after llvmir2hll is
//      loaded so that error message appear when the pattern finder is run, not
//      when llvmir2hll is executed.

/// A mapping of function names into a sequence of information about API calls
/// that begin with that function.
const APICallInfoSeqMap &API_CALL_INFO_SEQ_MAP(initAPICallInfoSeqMap());

} // anonymous namespace

/**
* @brief Constructs a pattern finder.
*
* See PatternFinder::PatternFinder() for more information.
*/
APICallSeqPatternFinder::APICallSeqPatternFinder(
	ShPtr<ValueAnalysis> va, ShPtr<CallInfoObtainer> cio):
		PatternFinder(va, cio), foundPatterns() {}

/**
* @brief Destructs the finder.
*/
APICallSeqPatternFinder::~APICallSeqPatternFinder() {}

/**
* @brief Creates and returns a new instance of APICallSeqPatternFinder.
*
* See PatternFinder::PatternFinder() for more information on the parameters and
* preconditions.
*/
ShPtr<PatternFinder> APICallSeqPatternFinder::create(
		ShPtr<ValueAnalysis> va, ShPtr<CallInfoObtainer> cio) {
	return ShPtr<PatternFinder>(new APICallSeqPatternFinder(va, cio));
}

const std::string APICallSeqPatternFinder::getId() const {
	return API_CALL_SEQ_PATTERN_FINDER_ID;
}

/**
* @brief Finds patterns in the given module and returns them.
*
* The returned patterns are instances of StmtsPattern.
*/
PatternFinder::Patterns APICallSeqPatternFinder::findPatterns(
		ShPtr<Module> module) {
	// TODO Add a possibility of setting APICallSeqFinder outside of this
	//      function.
	ShPtr<APICallSeqFinder> acf(new BasicBlockAPICallSeqFinder(va, cio));

	// For every call in the module...
	for (const auto &call : CallsInModuleObtainer::getCalls(module)) {
		std::string calledFuncName(getNameOfCalledFunc(call.call, module));
		if (calledFuncName.empty()) {
			continue;
		}

		// For every matching APICallInfoSeq...
		auto foundInfos = API_CALL_INFO_SEQ_MAP.equal_range(calledFuncName);
		while (foundInfos.first != foundInfos.second) {
			Patterns patterns(acf->findPatterns(foundInfos.first->second,
				call.call, call.stmt, call.func, call.module));
			for (const auto &pattern : patterns) {
				foundPatterns.push_back(pattern);
			}
			++foundInfos.first;
		}
	}
	return foundPatterns;
}

} // namespace llvmir2hll
} // namespace retdec

/**
* @file src/llvmir2hll/pattern/pattern_finders/api_call_pattern_finder.cpp
* @brief Implementation of APICallPatternFinder.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/value_analysis.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/obtainer/call_info_obtainer.h"
#include "retdec/llvmir2hll/obtainer/calls_in_module_obtainer.h"
#include "retdec/llvmir2hll/pattern/pattern_finder_factory.h"
#include "retdec/llvmir2hll/pattern/pattern_finders/api_call_pattern_finder.h"
#include "retdec/llvmir2hll/pattern/patterns/stmts_pattern.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/utils/container.h"

using retdec::utils::hasItem;

namespace retdec {
namespace llvmir2hll {

REGISTER_AT_FACTORY("APICall", API_CALL_PATTERN_FINDER_ID,
	PatternFinderFactory, APICallPatternFinder::create);

namespace {

/**
* @brief Returns the names of interesting functions.
*
* This function is intended to be used to initialize API_CALL_FUNC_NAMES.
*/
StringSet getAPICallFuncNames() {
	StringSet funcNames;

	// The following list is based on the "List of API sequences being logged
	// by GVMA64" document from AVG. Additionally, it contains all the A/W
	// variants.

	funcNames.insert("ShellExecute");
	funcNames.insert("ShellExecuteA");
	funcNames.insert("ShellExecuteW");
	funcNames.insert("CreateFile");
	funcNames.insert("CreateFileA");
	funcNames.insert("CreateFileW");
	funcNames.insert("OpenFile");
	funcNames.insert("ReadFile");
	funcNames.insert("WriteFile");

	funcNames.insert("fopen");
	funcNames.insert("fwopen");
	funcNames.insert("fread");
	funcNames.insert("fwrite");

	funcNames.insert("_open");
	funcNames.insert("_read");
	funcNames.insert("_write");

	funcNames.insert("CreateProcess");
	funcNames.insert("CreateProcessA");
	funcNames.insert("CreateProcessW");
	funcNames.insert("LoadModule");
	funcNames.insert("WinExec");
	funcNames.insert("ShellExecute");
	funcNames.insert("ShellExecuteA");
	funcNames.insert("ShellExecuteW");
	funcNames.insert("ShellExecuteEx");
	funcNames.insert("ShellExecuteExA");
	funcNames.insert("ShellExecuteExW");

	funcNames.insert("URLDownloadToFile");
	funcNames.insert("URLDownloadToFileA");
	funcNames.insert("URLDownloadToFileW");
	funcNames.insert("URLDownloadToCacheFile");
	funcNames.insert("URLDownloadToCacheFileA");
	funcNames.insert("URLDownloadToCacheFileW");

	funcNames.insert("RegOpenKey");
	funcNames.insert("RegOpenKeyA");
	funcNames.insert("RegOpenKeyW");
	funcNames.insert("RegOpenKeyEx");
	funcNames.insert("RegOpenKeyExA");
	funcNames.insert("RegOpenKeyExW");
	funcNames.insert("RegCreateKey");
	funcNames.insert("RegCreateKeyA");
	funcNames.insert("RegCreateKeyW");
	funcNames.insert("RegCreateKeyEx");
	funcNames.insert("RegCreateKeyExA");
	funcNames.insert("RegCreateKeyExW");
	funcNames.insert("RegSetValue");
	funcNames.insert("RegSetValueA");
	funcNames.insert("RegSetValueW");
	funcNames.insert("RegSetValueEx");
	funcNames.insert("RegSetValueExA");
	funcNames.insert("RegSetValueExW");

	funcNames.insert("LoadLibrary");
	funcNames.insert("LoadLibraryA");
	funcNames.insert("LoadLibraryW");

	funcNames.insert("CreateMutex");
	funcNames.insert("CreateMutexA");
	funcNames.insert("CreateMutexW");
	funcNames.insert("OpenMutex");
	funcNames.insert("OpenMutexA");
	funcNames.insert("OpenMutexW");
	funcNames.insert("CreateEvent");
	funcNames.insert("CreateEventA");
	funcNames.insert("CreateEventW");
	funcNames.insert("OpenEvent");
	funcNames.insert("OpenEventA");
	funcNames.insert("OpenEventW");

	funcNames.insert("CopyFile");
	funcNames.insert("CopyFileA");
	funcNames.insert("CopyFileW");
	funcNames.insert("CopyFileEx");
	funcNames.insert("CopyFileExA");
	funcNames.insert("CopyFileExW");
	funcNames.insert("MoveFile");
	funcNames.insert("MoveFileA");
	funcNames.insert("MoveFileW");
	funcNames.insert("MoveFileEx");
	funcNames.insert("MoveFileExA");
	funcNames.insert("MoveFileExW");
	funcNames.insert("DeleteFile");
	funcNames.insert("DeleteFileA");
	funcNames.insert("DeleteFileW");

	funcNames.insert("CreateService");
	funcNames.insert("CreateServiceA");
	funcNames.insert("CreateServiceW");

	return funcNames;
}

/// A set containing names of interesting functions.
const StringSet API_CALL_FUNC_NAMES(getAPICallFuncNames());

/// A list of calls.
using Calls = CallsInModuleObtainer::Calls;

/// A list of patterns.
using Patterns = PatternFinder::Patterns;

/**
* @brief Returns the list of API calls in given list of calls.
*/
Calls getAPICalls(const Calls &calls) {
	Calls apiCalls;
	for (const auto &call : calls) {
		ShPtr<Variable> funcVar(cast<Variable>(call.call->getCalledExpr()));
		if (funcVar && hasItem(API_CALL_FUNC_NAMES, funcVar->getName())) {
			apiCalls.push_back(call);
		}
	}
	return apiCalls;
}

/**
* @brief Makes a list of patterns from the given list of API calls.
*/
Patterns makePatterns(const Calls &apiCalls) {
	Patterns patterns;
	for (const auto &apiCall : apiCalls) {
		patterns.push_back(StmtsPattern::create(apiCall.stmt));
	}
	return patterns;
}

} // anonymous namespace

/**
* @brief Constructs a pattern finder.
*
* See PatternFinder::PatternFinder() for more information.
*/
APICallPatternFinder::APICallPatternFinder(
	ShPtr<ValueAnalysis> va, ShPtr<CallInfoObtainer> cio):
		PatternFinder(va, cio) {}

/**
* @brief Destructs the finder.
*/
APICallPatternFinder::~APICallPatternFinder() {}

/**
* @brief Creates and returns a new instance of APICallPatternFinder.
*
* See PatternFinder::PatternFinder() for more information on the parameters and
* preconditions.
*/
ShPtr<PatternFinder> APICallPatternFinder::create(
		ShPtr<ValueAnalysis> va, ShPtr<CallInfoObtainer> cio) {
	return ShPtr<PatternFinder>(new APICallPatternFinder(va, cio));
}

const std::string APICallPatternFinder::getId() const {
	return API_CALL_PATTERN_FINDER_ID;
}

/**
* @brief Finds patterns in the given module and returns them.
*
* The returned patterns are instances of StmtsPattern.
*/
PatternFinder::Patterns APICallPatternFinder::findPatterns(
		ShPtr<Module> module) {
	Calls allCalls(CallsInModuleObtainer::getCalls(module));
	Calls apiCalls(getAPICalls(allCalls));
	return makePatterns(apiCalls);
}

} // namespace llvmir2hll
} // namespace retdec

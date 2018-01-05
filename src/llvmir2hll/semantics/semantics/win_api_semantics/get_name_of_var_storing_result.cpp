/**
* @file src/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_var_storing_result.cpp
* @brief Implementation of semantics::win_api::getNameOfVarStoringResult() for
*        WinAPISemantics.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/semantics/semantics/impl_support/get_name_of_var_storing_result.h"
#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_var_storing_result.h"

namespace retdec {
namespace llvmir2hll {
namespace semantics {
namespace win_api {

namespace {

/**
* @brief This function is used to initialize FUNC_VAR_NAME_MAP later in the
*        file.
*/
const StringStringUMap &initFuncVarNameMap() {
	static StringStringUMap m;

	// The following list is based on
	//
	//     - MSDN database (http://msdn.microsoft.com/en-US/windows/)
	//
	// It is by all means not complete (only few functions are there). If you
	// find a function which is missing, please, add it.

	// windows.h
	m["ClientToScreen"] = "clientToScreenSuccess";
	m["CloseHandle"] = "handleClosed";
	m["CopyFile"] = "copyFileSuccess";
	m["CopyFileA"] = "copyFileSuccess";
	m["CreateFile"] = "fileHandle";
	m["CreateFileA"] = "fileHandle";
	m["CreateThread"] = "threadHandle";
	m["CreateWindowEx"] = "windowHandle";
	m["CreateWindowExA"] = "windowHandle";
	m["EqualRect"] = "equalRect";
	m["GetActiveWindow"] = "windowHandle";
	m["GetBkColor"] = "color";
	m["GetBkMode"] = "mode";
	m["GetCommandLine"] = "commandLine";
	m["GetCommandLineA"] = "commandLine";
	m["GetCurrentProcess"] = "processHandle";
	m["GetCurrentProcessId"] = "processId";
	m["GetCurrentThread"] = "threadHandle";
	m["GetCurrentThreadId"] = "threadId";
	m["GetDriveType"] = "driveType";
	m["GetDriveTypeA"] = "driveType";
	m["GetFocus"] = "windowHandle";
	m["GetForegroundWindow"] = "windowHandle";
	m["GetLastError"] = "errorCode";
	m["GetLogicalDrives"] = "availDiskDrives";
	m["GetModuleFileName"] = "nameSize";
	m["GetModuleFileNameA"] = "nameSize";
	m["GetModuleHandle"] = "moduleHandle";
	m["GetModuleHandleA"] = "moduleHandle";
	m["GetProcAddress"] = "func";
	m["GetSystemDefaultLangID"] = "langId";
	m["GetTempPath"] = "pathSize";
	m["GetTempPathA"] = "pathSize";
	m["GetThreadPriority"] = "threadPriority";
	m["IsValidCodePage"] = "validCodePage";
	m["IsWindowVisible"] = "isVisible";
	m["LoadCursor"] = "cursorHandle";
	m["LoadCursorA"] = "cursorHandle";
	m["LoadIcon"] = "iconHandle";
	m["LoadIconA"] = "iconHandle";
	m["LoadLibrary"] = "moduleHandle";
	m["LoadLibraryA"] = "moduleHandle";
	m["LocalAlloc"] = "memoryHandle";
	m["RegisterClassEx"] = "classAtom";
	m["RegisterClassExA"] = "classAtom";
	m["SetTimer"] = "timerId";
	m["SetUnhandledExceptionFilter"] = "prevExceptionFilter";
	m["VirtualAlloc"] = "memory";

	return m;
}

/// Mapping of function names to their corresponding names of variables.
const StringStringUMap &FUNC_VAR_NAME_MAP(initFuncVarNameMap());

} // anonymous namespace

/**
* @brief Implements getNameOfVarStoringResult() for WinAPISemantics.
*
* See its description for more details.
*/
Maybe<std::string> getNameOfVarStoringResult(const std::string &funcName) {
	return getNameOfVarStoringResultFromMap(funcName, FUNC_VAR_NAME_MAP);
}

} // namespace win_api
} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec

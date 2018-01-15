/**
* @file src/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/n.cpp
* @brief Implementation of the initialization of WinAPI functions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/n.h"

namespace retdec {
namespace llvmir2hll {
namespace semantics {
namespace win_api {

/**
* @brief Initializes the given map with info about functions starting with N.
*/
void initFuncParamNamesMap_N(FuncParamNamesMap &funcParamNamesMap) {
	//
	// windows.h
	//
	ADD_PARAM_NAME("NeedCurrentDirectoryForExePathA", 1, "ExeName"); // LPCSTR
	ADD_PARAM_NAME("NeedCurrentDirectoryForExePathW", 1, "ExeName"); // LPCWSTR
	ADD_PARAM_NAME("NormalizeString", 1, "NormForm"); // NORM_FORM
	ADD_PARAM_NAME("NormalizeString", 2, "lpSrcString"); // LPCWSTR
	ADD_PARAM_NAME("NormalizeString", 3, "cwSrcLength"); // int
	ADD_PARAM_NAME("NormalizeString", 4, "lpDstString"); // LPWSTR
	ADD_PARAM_NAME("NormalizeString", 5, "cwDstLength"); // int
	ADD_PARAM_NAME("NotifyBootConfigStatus", 1, "BootAcceptable"); // WINBOOL
	ADD_PARAM_NAME("NotifyChangeEventLog", 1, "hEventLog"); // HANDLE
	ADD_PARAM_NAME("NotifyChangeEventLog", 2, "hEvent"); // HANDLE
	ADD_PARAM_NAME("NotifyServiceStatusChangeA", 1, "hService"); // SC_HANDLE
	ADD_PARAM_NAME("NotifyServiceStatusChangeA", 2, "dwNotifyMask"); // DWORD
	ADD_PARAM_NAME("NotifyServiceStatusChangeA", 3, "pNotifyBuffer"); // PSERVICE_NOTIFYA
	ADD_PARAM_NAME("NotifyServiceStatusChangeW", 1, "hService"); // SC_HANDLE
	ADD_PARAM_NAME("NotifyServiceStatusChangeW", 2, "dwNotifyMask"); // DWORD
	ADD_PARAM_NAME("NotifyServiceStatusChangeW", 3, "pNotifyBuffer"); // PSERVICE_NOTIFYW
	ADD_PARAM_NAME("NotifyWinEvent", 1, "event"); // DWORD
	ADD_PARAM_NAME("NotifyWinEvent", 2, "hWnd"); // HWND
	ADD_PARAM_NAME("NotifyWinEvent", 3, "idObject"); // LONG
	ADD_PARAM_NAME("NotifyWinEvent", 4, "idChild"); // LONG
}

} // namespace win_api
} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec

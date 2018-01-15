/**
* @file src/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/k.cpp
* @brief Implementation of the initialization of WinAPI functions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/k.h"

namespace retdec {
namespace llvmir2hll {
namespace semantics {
namespace win_api {

/**
* @brief Initializes the given map with info about functions starting with K.
*/
void initFuncParamNamesMap_K(FuncParamNamesMap &funcParamNamesMap) {
	//
	// windows.h
	//
	ADD_PARAM_NAME("KillTimer", 1, "hWnd"); // HWND
	ADD_PARAM_NAME("KillTimer", 2, "uIDEvent"); // UINT_PTR

	ADD_PARAM_NAME("keybd_event", 1, "bVk"); // BYTE
	ADD_PARAM_NAME("keybd_event", 2, "bScan"); // BYTE
	ADD_PARAM_NAME("keybd_event", 3, "dwFlags"); // DWORD
	ADD_PARAM_NAME("keybd_event", 4, "dwExtraInfo"); // ULONG_PTR
}

} // namespace win_api
} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec

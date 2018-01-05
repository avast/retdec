/**
* @file src/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/x.cpp
* @brief Implementation of the initialization of WinAPI functions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/x.h"

namespace retdec {
namespace llvmir2hll {
namespace semantics {
namespace win_api {

/**
* @brief Initializes the given map with info about functions starting with X.
*/
void initFuncParamNamesMap_X(FuncParamNamesMap &funcParamNamesMap) {
	//
	// windows.h
	//
	ADD_PARAM_NAME("XcvDataW", 1, "hXcv"); // HANDLE
	ADD_PARAM_NAME("XcvDataW", 2, "pszDataName"); // PCWSTR
	ADD_PARAM_NAME("XcvDataW", 3, "pInputData"); // PBYTE
	ADD_PARAM_NAME("XcvDataW", 4, "cbInputData"); // DWORD
	ADD_PARAM_NAME("XcvDataW", 5, "pOutputData"); // PBYTE
	ADD_PARAM_NAME("XcvDataW", 6, "cbOutputData"); // DWORD
	ADD_PARAM_NAME("XcvDataW", 7, "pcbOutputNeeded"); // PDWORD
	ADD_PARAM_NAME("XcvDataW", 8, "pdwStatus"); // PDWORD
}

} // namespace win_api
} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec

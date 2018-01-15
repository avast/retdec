/**
* @file src/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/z.cpp
* @brief Implementation of the initialization of WinAPI functions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/z.h"

namespace retdec {
namespace llvmir2hll {
namespace semantics {
namespace win_api {

/**
* @brief Initializes the given map with info about functions starting with Z.
*/
void initFuncParamNamesMap_Z(FuncParamNamesMap &funcParamNamesMap) {
	//
	// windows.h
	//
	ADD_PARAM_NAME("ZombifyActCtx", 1, "hActCtx"); // HANDLE
}

} // namespace win_api
} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec

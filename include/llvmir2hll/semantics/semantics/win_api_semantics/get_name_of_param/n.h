/**
* @file include/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/n.h
* @brief Initializes FuncParamNamesMap for WinAPI functions starting with N.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef LLVMIR2HLL_SEMANTICS_SEMANTICS_WIN_API_SEMANTICS_GET_NAME_OF_PARAM_N_H
#define LLVMIR2HLL_SEMANTICS_SEMANTICS_WIN_API_SEMANTICS_GET_NAME_OF_PARAM_N_H

#include "llvmir2hll/semantics/semantics/impl_support/get_name_of_param.h"

namespace llvmir2hll {
namespace semantics {
namespace win_api {

void initFuncParamNamesMap_N(FuncParamNamesMap &funcParamNamesMap);

} // namespace win_api
} // namespace semantics
} // namespace llvmir2hll

#endif

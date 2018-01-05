/**
* @file include/retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/m.h
* @brief Initializes FuncParamNamesMap for WinAPI functions starting with M.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_SEMANTICS_SEMANTICS_WIN_API_SEMANTICS_GET_NAME_OF_PARAM_M_H
#define RETDEC_LLVMIR2HLL_SEMANTICS_SEMANTICS_WIN_API_SEMANTICS_GET_NAME_OF_PARAM_M_H

#include "retdec/llvmir2hll/semantics/semantics/impl_support/get_name_of_param.h"

namespace retdec {
namespace llvmir2hll {
namespace semantics {
namespace win_api {

void initFuncParamNamesMap_M(FuncParamNamesMap &funcParamNamesMap);

} // namespace win_api
} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec

#endif

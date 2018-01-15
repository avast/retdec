/**
* @file src/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param.cpp
* @brief Implementation of semantics::win_api::getNameOfParam() for
*        WinAPISemantics.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/semantics/semantics/impl_support/get_name_of_param.h"
#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param.h"
#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/a.h"
#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/b.h"
#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/c1.h"
#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/c2.h"
#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/d.h"
#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/e.h"
#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/f.h"
#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/g1.h"
#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/g2.h"
#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/h.h"
#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/i.h"
#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/j.h"
#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/k.h"
#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/l.h"
#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/m.h"
#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/n.h"
#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/o.h"
#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/p.h"
#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/q.h"
#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/r.h"
#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/s.h"
#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/t.h"
#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/u.h"
#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/v.h"
#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/w.h"
#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/x.h"
#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/y.h"
#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param/z.h"

namespace retdec {
namespace llvmir2hll {
namespace semantics {
namespace win_api {

namespace {

/**
* @brief This function is used to initialize FUNC_PARAM_NAMES_MAP later in the
*        file.
*/
const FuncParamNamesMap &initFuncParamNamesMap() {
	static FuncParamNamesMap funcParamNamesMap;

	//
	// The base of the information for this type of semantics has been obtained
	// by using the
	// scripts/backend/semantics/func_var_names/gen_winapi_semantics_from_includes.py
	// script with includes mingw32-x86-pe/i686-w64-mingw32/includes/win*.h.
	// The resulting semantics has been updated manually. Useless mappings have
	// been commented out.
	//

	// Since having 10 000 lines in a single file was found impossible to
	// compile by using gcc in a reasonable amount of time and memory (even
	// using -fno-var-tracking), we had to split the initialization into
	// several modules.
	initFuncParamNamesMap_A(funcParamNamesMap);
	initFuncParamNamesMap_B(funcParamNamesMap);
	initFuncParamNamesMap_C1(funcParamNamesMap);
	initFuncParamNamesMap_C2(funcParamNamesMap);
	initFuncParamNamesMap_D(funcParamNamesMap);
	initFuncParamNamesMap_E(funcParamNamesMap);
	initFuncParamNamesMap_F(funcParamNamesMap);
	initFuncParamNamesMap_G1(funcParamNamesMap);
	initFuncParamNamesMap_G2(funcParamNamesMap);
	initFuncParamNamesMap_H(funcParamNamesMap);
	initFuncParamNamesMap_I(funcParamNamesMap);
	initFuncParamNamesMap_J(funcParamNamesMap);
	initFuncParamNamesMap_K(funcParamNamesMap);
	initFuncParamNamesMap_L(funcParamNamesMap);
	initFuncParamNamesMap_M(funcParamNamesMap);
	initFuncParamNamesMap_N(funcParamNamesMap);
	initFuncParamNamesMap_O(funcParamNamesMap);
	initFuncParamNamesMap_P(funcParamNamesMap);
	initFuncParamNamesMap_Q(funcParamNamesMap);
	initFuncParamNamesMap_R(funcParamNamesMap);
	initFuncParamNamesMap_S(funcParamNamesMap);
	initFuncParamNamesMap_T(funcParamNamesMap);
	initFuncParamNamesMap_U(funcParamNamesMap);
	initFuncParamNamesMap_V(funcParamNamesMap);
	initFuncParamNamesMap_W(funcParamNamesMap);
	initFuncParamNamesMap_X(funcParamNamesMap);
	initFuncParamNamesMap_Y(funcParamNamesMap);
	initFuncParamNamesMap_Z(funcParamNamesMap);

	return funcParamNamesMap;
}

/// Mapping of function parameter positions into the names of parameters.
const FuncParamNamesMap &FUNC_PARAM_NAMES_MAP(initFuncParamNamesMap());

} // anonymous namespace

/**
* @brief Implements getNameOfParam() for WinAPISemantics.
*
* See its description for more details.
*/
Maybe<std::string> getNameOfParam(const std::string &funcName,
		unsigned paramPos) {
	return getNameOfParamFromMap(funcName, paramPos, FUNC_PARAM_NAMES_MAP);
}

} // namespace win_api
} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec

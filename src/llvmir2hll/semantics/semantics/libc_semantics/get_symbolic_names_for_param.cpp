/**
* @file src/llvmir2hll/semantics/semantics/libc_semantics/get_symbolic_names_for_param.cpp
* @brief Implementation of semantics::libc::getSymbolicNamesForParam() for
*        LibcSemantics.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/semantics/semantics/impl_support/get_symbolic_names_for_param.h"
#include "retdec/llvmir2hll/semantics/semantics/libc_semantics/get_symbolic_names_for_param.h"

namespace retdec {
namespace llvmir2hll {
namespace semantics {
namespace libc {

namespace {

/**
* @brief This function is used to initialize FUNC_PARAMS_MAP later in the file.
*/
const FuncParamsMap &initFuncParamsMap() {
	static FuncParamsMap funcParamsMap;

	// Temporary maps used to store the symbols for the current parameter of
	// the current function. In this way, we don't have to keep separate maps
	// for every function and every parameter. The only downside is that before
	// adding new data into it, it has to be cleared.
	ParamSymbolsMap paramSymbolsMap;
	IntStringMap symbolicNamesMap;

	//
	// #include <stdio.h>
	// int fseek(FILE *stream, long offset, int whence);
	//
	// Info from: <stdio.h>
	//
	paramSymbolsMap.clear();
	// whence
	symbolicNamesMap.clear();
	symbolicNamesMap[0] = "SEEK_SET";
	symbolicNamesMap[1] = "SEEK_CUR";
	symbolicNamesMap[2] = "SEEK_END";
	paramSymbolsMap[3] = symbolicNamesMap;
	funcParamsMap["fseek"] = paramSymbolsMap;

	return funcParamsMap;
}

/// Mapping of function names into symbolic names of their parameters.
const FuncParamsMap &FUNC_PARAMS_MAP(initFuncParamsMap());

} // anonymous namespace

/**
* @brief Implements getSymbolicNamesForParam() for LibcSemantics.
*
* See its description for more details.
*/
Maybe<IntStringMap> getSymbolicNamesForParam(const std::string &funcName,
		unsigned paramPos) {
	return getSymbolicNamesForParamFromMap(funcName, paramPos, FUNC_PARAMS_MAP);
}

} // namespace libc
} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec

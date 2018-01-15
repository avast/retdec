/**
* @file src/llvmir2hll/semantics/semantics/gcc_general_semantics/get_name_of_var_storing_result.cpp
* @brief Implementation of semantics::gcc_general::getNameOfVarStoringResult()
*        for GCCGeneralSemantics.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/semantics/semantics/impl_support/get_name_of_var_storing_result.h"
#include "retdec/llvmir2hll/semantics/semantics/libc_semantics/get_name_of_var_storing_result.h"

namespace retdec {
namespace llvmir2hll {
namespace semantics {
namespace gcc_general {

namespace {

/**
* @brief This function is used to initialize FUNC_VAR_NAME_MAP later in the
*        file.
*/
const StringStringUMap &initFuncVarNameMap() {
	static StringStringUMap m;

	// TODO Add more mappings.

	// signal.h
	m["signal"] = "prev_func_h";

	// sys/socket.h
	m["accept"] = "accepted_sock_fd";
	m["socket"] = "sock_fd";

	// sys/stat.h
	m["open"] = "fd";

	// unistd.h
	m["getpid"] = "pid";
	m["getppid"] = "ppid";

	return m;
}

/// Mapping of function names to their corresponding names of variables.
const StringStringUMap &FUNC_VAR_NAME_MAP(initFuncVarNameMap());

} // anonymous namespace

/**
* @brief Implements getNameOfVarStoringResult() for GCCGeneralSemantics.
*
* See its description for more details.
*/
Maybe<std::string> getNameOfVarStoringResult(const std::string &funcName) {
	return getNameOfVarStoringResultFromMap(funcName, FUNC_VAR_NAME_MAP);
}

} // namespace gcc_general
} // namespace semantics
} // namespace llvmir2hll
} // namespace retdec

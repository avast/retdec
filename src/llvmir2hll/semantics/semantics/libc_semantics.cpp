/**
* @file src/llvmir2hll/semantics/semantics/libc_semantics.cpp
* @brief Implementation of LibcSemantics.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/semantics/semantics/libc_semantics.h"
#include "retdec/llvmir2hll/semantics/semantics/libc_semantics/func_never_returns.h"
#include "retdec/llvmir2hll/semantics/semantics/libc_semantics/get_c_header_file_for_func.h"
#include "retdec/llvmir2hll/semantics/semantics/libc_semantics/get_name_of_param.h"
#include "retdec/llvmir2hll/semantics/semantics/libc_semantics/get_name_of_var_storing_result.h"
#include "retdec/llvmir2hll/semantics/semantics/libc_semantics/get_symbolic_names_for_param.h"
#include "retdec/llvmir2hll/semantics/semantics_factory.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/types.h"

namespace retdec {
namespace llvmir2hll {

REGISTER_AT_FACTORY("libc", LIBC_SEMANTICS_ID, SemanticsFactory,
	LibcSemantics::create);

/**
* @brief Constructs the semantics.
*/
LibcSemantics::LibcSemantics() {}

/**
* @brief Creates a new semantics.
*/
ShPtr<Semantics> LibcSemantics::create() {
	return ShPtr<Semantics>(new LibcSemantics());
}

std::string LibcSemantics::getId() const {
	return LIBC_SEMANTICS_ID;
}

Maybe<std::string> LibcSemantics::getMainFuncName() const {
	return Just<std::string>("main");
}

Maybe<std::string> LibcSemantics::getCHeaderFileForFunc(
		const std::string &funcName) const {
	return semantics::libc::getCHeaderFileForFunc(funcName);
}

Maybe<bool> LibcSemantics::funcNeverReturns(
		const std::string &funcName) const {
	return semantics::libc::funcNeverReturns(funcName);
}

Maybe<std::string> LibcSemantics::getNameOfVarStoringResult(
		const std::string &funcName) const {
	return semantics::libc::getNameOfVarStoringResult(funcName);
}

Maybe<std::string> LibcSemantics::getNameOfParam(
		const std::string &funcName, unsigned paramPos) const {
	return semantics::libc::getNameOfParam(funcName, paramPos);
}

Maybe<IntStringMap> LibcSemantics::getSymbolicNamesForParam(
		const std::string &funcName, unsigned paramPos) const {
	return semantics::libc::getSymbolicNamesForParam(funcName, paramPos);
}

} // namespace llvmir2hll
} // namespace retdec

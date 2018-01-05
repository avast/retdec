/**
* @file src/llvmir2hll/semantics/semantics/win_api_semantics.cpp
* @brief Implementation of WinAPISemantics.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics.h"
#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/func_never_returns.h"
#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_c_header_file_for_func.h"
#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_param.h"
#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_name_of_var_storing_result.h"
#include "retdec/llvmir2hll/semantics/semantics/win_api_semantics/get_symbolic_names_for_param.h"
#include "retdec/llvmir2hll/semantics/semantics_factory.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/types.h"

namespace retdec {
namespace llvmir2hll {

REGISTER_AT_FACTORY("win-api", WIN_API_SEMANTICS_ID, SemanticsFactory,
	WinAPISemantics::create);

/**
* @brief Constructs the semantics.
*/
WinAPISemantics::WinAPISemantics() {}

/**
* @brief Creates a new semantics.
*/
ShPtr<Semantics> WinAPISemantics::create() {
	return ShPtr<Semantics>(new WinAPISemantics());
}

std::string WinAPISemantics::getId() const {
	return WIN_API_SEMANTICS_ID;
}

Maybe<std::string> WinAPISemantics::getCHeaderFileForFunc(
		const std::string &funcName) const {
	return semantics::win_api::getCHeaderFileForFunc(funcName);
}

Maybe<bool> WinAPISemantics::funcNeverReturns(
		const std::string &funcName) const {
	return semantics::win_api::funcNeverReturns(funcName);
}

Maybe<std::string> WinAPISemantics::getNameOfVarStoringResult(
		const std::string &funcName) const {
	return semantics::win_api::getNameOfVarStoringResult(funcName);
}

Maybe<std::string> WinAPISemantics::getNameOfParam(
		const std::string &funcName, unsigned paramPos) const {
	return semantics::win_api::getNameOfParam(funcName, paramPos);
}

Maybe<IntStringMap> WinAPISemantics::getSymbolicNamesForParam(
		const std::string &funcName, unsigned paramPos) const {
	return semantics::win_api::getSymbolicNamesForParam(funcName, paramPos);
}

} // namespace llvmir2hll
} // namespace retdec

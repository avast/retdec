/**
* @file src/llvmir2hll/semantics/semantics/gcc_general_semantics.cpp
* @brief Implementation of GCCGeneralSemantics.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/semantics/semantics/gcc_general_semantics.h"
#include "retdec/llvmir2hll/semantics/semantics/gcc_general_semantics/get_c_header_file_for_func.h"
#include "retdec/llvmir2hll/semantics/semantics/gcc_general_semantics/get_name_of_param.h"
#include "retdec/llvmir2hll/semantics/semantics/gcc_general_semantics/get_name_of_var_storing_result.h"
#include "retdec/llvmir2hll/semantics/semantics/gcc_general_semantics/get_symbolic_names_for_param.h"
#include "retdec/llvmir2hll/semantics/semantics_factory.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/types.h"

namespace retdec {
namespace llvmir2hll {

REGISTER_AT_FACTORY("gcc-general", GCC_GENERAL_SEMANTICS_ID, SemanticsFactory,
	GCCGeneralSemantics::create);

/**
* @brief Constructs the semantics.
*/
GCCGeneralSemantics::GCCGeneralSemantics() {}

/**
* @brief Creates a new semantics.
*/
ShPtr<Semantics> GCCGeneralSemantics::create() {
	return ShPtr<Semantics>(new GCCGeneralSemantics());
}

std::string GCCGeneralSemantics::getId() const {
	return GCC_GENERAL_SEMANTICS_ID;
}

Maybe<std::string> GCCGeneralSemantics::getCHeaderFileForFunc(
		const std::string &funcName) const {
	return semantics::gcc_general::getCHeaderFileForFunc(funcName);
}

Maybe<std::string> GCCGeneralSemantics::getNameOfVarStoringResult(
		const std::string &funcName) const {
	return semantics::gcc_general::getNameOfVarStoringResult(funcName);
}

Maybe<std::string> GCCGeneralSemantics::getNameOfParam(
		const std::string &funcName, unsigned paramPos) const {
	return semantics::gcc_general::getNameOfParam(funcName, paramPos);
}

Maybe<IntStringMap> GCCGeneralSemantics::getSymbolicNamesForParam(
		const std::string &funcName, unsigned paramPos) const {
	return semantics::gcc_general::getSymbolicNamesForParam(funcName, paramPos);
}

} // namespace llvmir2hll
} // namespace retdec

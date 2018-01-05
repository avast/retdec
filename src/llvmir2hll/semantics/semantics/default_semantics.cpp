/**
* @file src/llvmir2hll/semantics/semantics/default_semantics.cpp
* @brief Implementation of DefaultSemantics.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/semantics/semantics/default_semantics.h"
#include "retdec/llvmir2hll/semantics/semantics_factory.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

REGISTER_AT_FACTORY("default", DEFAULT_SEMANTICS_ID, SemanticsFactory,
	DefaultSemantics::create);

/**
* @brief Constructs the semantics.
*/
DefaultSemantics::DefaultSemantics() {}

/**
* @brief Creates a new semantics.
*/
ShPtr<Semantics> DefaultSemantics::create() {
	return ShPtr<Semantics>(new DefaultSemantics());
}

std::string DefaultSemantics::getId() const {
	return DEFAULT_SEMANTICS_ID;
}

Maybe<std::string> DefaultSemantics::getMainFuncName() const {
	return Nothing<std::string>();
}

Maybe<std::string> DefaultSemantics::getCHeaderFileForFunc(
		const std::string &funcName) const {
	return Nothing<std::string>();
}

Maybe<bool> DefaultSemantics::funcNeverReturns(
		const std::string &funcName) const {
	return Nothing<bool>();
}

Maybe<std::string> DefaultSemantics::getNameOfVarStoringResult(
		const std::string &funcName) const {
	return Nothing<std::string>();
}

Maybe<std::string> DefaultSemantics::getNameOfParam(
		const std::string &funcName, unsigned paramPos) const {
	return Nothing<std::string>();
}

Maybe<IntStringMap> DefaultSemantics::getSymbolicNamesForParam(
		const std::string &funcName, unsigned paramPos) const {
	return Nothing<IntStringMap>();
}

} // namespace llvmir2hll
} // namespace retdec

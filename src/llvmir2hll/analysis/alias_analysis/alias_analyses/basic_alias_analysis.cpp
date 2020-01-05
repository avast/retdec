/**
* @file src/llvmir2hll/analysis/alias_analysis/alias_analyses/basic_alias_analysis.cpp
* @brief Implementation of BasicAliasAnalysis.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/alias_analysis/alias_analyses/basic_alias_analysis.h"
#include "retdec/llvmir2hll/analysis/alias_analysis/alias_analysis_factory.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

REGISTER_AT_FACTORY("basic", BASIC_ALIAS_ANALYSIS_ID, AliasAnalysisFactory,
	BasicAliasAnalysis::create);

/**
* @brief Constructs a new analysis.
*/
BasicAliasAnalysis::BasicAliasAnalysis(): AliasAnalysis() {}

/**
* @brief Creates a new basic alias analysis.
*/
AliasAnalysis* BasicAliasAnalysis::create() {
	return nullptr;
}

std::string BasicAliasAnalysis::getId() const {
	return BASIC_ALIAS_ANALYSIS_ID;
}

void BasicAliasAnalysis::init(Module* module) {
	AliasAnalysis::init(module);
}

} // namespace llvmir2hll
} // namespace retdec

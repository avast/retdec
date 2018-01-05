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
* @brief Destructs the analysis.
*/
BasicAliasAnalysis::~BasicAliasAnalysis() {}

/**
* @brief Creates a new basic alias analysis.
*/
ShPtr<AliasAnalysis> BasicAliasAnalysis::create() {
	return ShPtr<BasicAliasAnalysis>();

	// TODO Uncomment after all pure virtual methods from the base class are
	//      implemented.
	// return ShPtr<BasicAliasAnalysis>(new BasicAliasAnalysis());
}

std::string BasicAliasAnalysis::getId() const {
	return BASIC_ALIAS_ANALYSIS_ID;
}

void BasicAliasAnalysis::init(ShPtr<Module> module) {
	AliasAnalysis::init(module);
}

} // namespace llvmir2hll
} // namespace retdec

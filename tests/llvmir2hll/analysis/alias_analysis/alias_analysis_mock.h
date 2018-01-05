/**
* @file tests/llvmir2hll/analysis/alias_analysis/alias_analysis_mock.h
* @brief A mock for the AliasAnalysis module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef BACKEND_BIR_ANALYSIS_ALIAS_ANALYSIS_TESTS_ALIAS_ANALYSIS_MOCK_H
#define BACKEND_BIR_ANALYSIS_ALIAS_ANALYSIS_TESTS_ALIAS_ANALYSIS_MOCK_H

#include <gmock/gmock.h>

#include "retdec/llvmir2hll/analysis/alias_analysis/alias_analysis.h"

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief A mock for the AliasAnalysis module.
*/
class AliasAnalysisMock: public AliasAnalysis {
public:
	MOCK_METHOD1(init, void (ShPtr<Module> module));
	MOCK_CONST_METHOD0(isInitialized, bool ());
	MOCK_CONST_METHOD1(mayPointTo, const VarSet & (ShPtr<Variable> var));
	MOCK_CONST_METHOD1(pointsTo, ShPtr<Variable> (ShPtr<Variable> var));
	MOCK_CONST_METHOD1(mayBePointed, bool (ShPtr<Variable> var));
	MOCK_CONST_METHOD0(getId, std::string ());
};

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec

#endif

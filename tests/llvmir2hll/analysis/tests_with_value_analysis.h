/**
* @file tests/llvmir2hll/analysis/tests_with_value_analysis.h
* @brief Support for tests using ValueAnalysis.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef BACKEND_BIR_ANALYSIS_TESTS_TESTS_WITH_VALUE_ANALYSIS_H
#define BACKEND_BIR_ANALYSIS_TESTS_TESTS_WITH_VALUE_ANALYSIS_H

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "llvmir2hll/analysis/alias_analysis/alias_analysis_mock.h"
#include "retdec/llvmir2hll/analysis/value_analysis.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

/**
* @brief Instantiates AliasAnalysisMock, AliasAnalysis, and ValueAnalysis using
*        the given module.
*
* This macro does the following:
*  (1) Instantiates AliasAnalysisMock and AliasAnalysis (variables @c
*      aliasAnalysisMock and @c aliasAnalysis).
*  (2) Sets-up default actions for aliasAalysisMock.
*  (3) Instantiates a ValueAnalysis (variable @c va).
*
* Example of usage:
* @code
* TEST(TestExample, Test1) {
*   // Set-up a module.
*   INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module);
*   // Set-up custom default actions or expectations for aliasAnalysisMock.
*   // Run tests utilizing ValueAnalysis.
* }
* @endcode
*/
#define INSTANTIATE_ALIAS_ANALYSIS_AND_VALUE_ANALYSIS(module) \
	/* (1) */ \
	::testing::NiceMock<AliasAnalysisMock> *aliasAnalysisMock = \
		new ::testing::NiceMock<AliasAnalysisMock>(); \
	ShPtr<AliasAnalysis> aliasAnalysis(aliasAnalysisMock); \
	/* (2) */ \
	const VarSet EMPTY_VAR_SET; \
	ON_CALL(*aliasAnalysisMock, mayPointTo(::testing::_)) \
		.WillByDefault(::testing::ReturnRef(EMPTY_VAR_SET)); \
	ON_CALL(*aliasAnalysisMock, pointsTo(::testing::_)) \
		.WillByDefault(::testing::Return(ShPtr<Variable>())); \
	ON_CALL(*aliasAnalysisMock, mayBePointed(::testing::_)) \
		.WillByDefault(::testing::Return(false)); \
	ON_CALL(*aliasAnalysisMock, isInitialized()) \
		.WillByDefault(::testing::Return(true)); \
	/* (3) */ \
	ShPtr<ValueAnalysis> va(ValueAnalysis::create(aliasAnalysis, false))

#endif

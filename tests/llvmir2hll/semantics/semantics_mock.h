/**
* @file tests/llvmir2hll/semantics/semantics_mock.h
* @brief A mock for the Semantics module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef BACKEND_BIR_SEMANTICS_TESTS_SEMANTICS_MOCK_H
#define BACKEND_BIR_SEMANTICS_TESTS_SEMANTICS_MOCK_H

#include <gmock/gmock.h>

#include "retdec/llvmir2hll/semantics/semantics.h"

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief A mock for the Semantics module.
*/
class SemanticsMock: public Semantics {
public:
	MOCK_CONST_METHOD0(getId, std::string ());
	MOCK_CONST_METHOD0(getMainFuncName, Maybe<std::string> ());
	MOCK_CONST_METHOD1(getCHeaderFileForFunc,
		Maybe<std::string> (const std::string &));
	MOCK_CONST_METHOD1(funcNeverReturns,
		Maybe<bool> (const std::string &));
	MOCK_CONST_METHOD1(getNameOfVarStoringResult,
		Maybe<std::string> (const std::string &));
	MOCK_CONST_METHOD2(getNameOfParam,
		Maybe<std::string> (const std::string &, unsigned));
	MOCK_CONST_METHOD2(getSymbolicNamesForParam,
		Maybe<IntStringMap> (const std::string &, unsigned));
};

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec

/**
* @brief Instantiates SemanticsMock with the given name.
*
* More specifically, this macro instantiates two classes:
*  (1) @c semanticsNameMock, which is of type
*      @code
*      ::testing::NiceMock<SemanticsMock> *
*      @endcode
*  (2) @c semanticsName, which is of type
*      @code
*      ShPtr<Semantics>
*      @endcode
*      and delegates to the mock from (1).
*/
#define INSTANTIATE_SEMANTICS_MOCK(semanticsName) \
	::testing::NiceMock<SemanticsMock> *semanticsName##Mock = \
		new ::testing::NiceMock<SemanticsMock>(); \
	ShPtr<Semantics> semanticsName(semanticsName##Mock);

#endif

/**
* @file tests/llvmir2hll/pattern/pattern_finders/api_call/api_call_info_tests.cpp
* @brief Tests for the @c api_call_info module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/pattern/pattern_finders/api_call/api_call_info.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c api_call_info module.
*/
class APICallInfoTests: public ::testing::Test {};

//
// APICallInfo()
//

#if DEATH_TESTS_ENABLED
TEST_F(APICallInfoTests,
CreatingInfoWithEmptyFuncNameResultsIntoViolatedPrecondition) {
	EXPECT_DEATH(APICallInfo(""), ".*Precondition.*failed.*");
}
#endif

//
// Copy constructor
//
TEST_F(APICallInfoTests,
CopyConstructionWorkCorrectly) {
	APICallInfo info1("test");
	info1.bindReturnValue("X");
	info1.bindParam(1, "Y");
	APICallInfo info2(info1);
	EXPECT_EQ(info1, info2);
}

//
// operator=()
//

TEST_F(APICallInfoTests,
AssignmentToOtherInfoWorkCorrectly) {
	APICallInfo info1("test");
	info1.bindReturnValue("X");
	info1.bindParam(1, "Y");
	APICallInfo info2("test2");
	info2 = info1;
	EXPECT_EQ(info1, info2);
}

TEST_F(APICallInfoTests,
AssignmentToSelfWorksCorrectly) {
	APICallInfo info("test");
	info = info;
	EXPECT_EQ("test", info.getFuncName());
}

//
// operator==()
// operator!=()
//

TEST_F(APICallInfoTests,
TwoAPICallInfosHavingTheSameDataAreQual) {
	APICallInfo info1("test");
	info1.bindReturnValue("X");
	info1.bindParam(1, "Y");
	info1.bindParam(2, "Y");
	APICallInfo info2("test");
	info2.bindReturnValue("X");
	info2.bindParam(1, "Y");
	info2.bindParam(2, "Y");
	EXPECT_EQ(info1, info2);
	EXPECT_EQ(info2, info1);
}

TEST_F(APICallInfoTests,
TwoAPICallInfosHavingDifferentFunctionNameAreNotEqual) {
	APICallInfo info1("test1");
	APICallInfo info2("test2");
	EXPECT_NE(info1, info2);
	EXPECT_NE(info2, info1);
}

TEST_F(APICallInfoTests,
TwoAPICallInfosHavingDifferentReturnValueBindAreNotEqual) {
	APICallInfo info1("test");
	info1.bindReturnValue("X");
	APICallInfo info2("test");
	info1.bindReturnValue("Y");
	EXPECT_NE(info1, info2);
	EXPECT_NE(info2, info1);
}

TEST_F(APICallInfoTests,
TwoAPICallInfosHavingDifferentParameterBindsAreNotEqual) {
	APICallInfo info1("test");
	info1.bindParam(1, "X");
	APICallInfo info2("test");
	info1.bindParam(1, "Y");
	EXPECT_NE(info1, info2);
	EXPECT_NE(info2, info1);
}

//
// getFuncName()
//

TEST_F(APICallInfoTests,
GetFuncNameReturnsCorrectName) {
	APICallInfo info("test");
	EXPECT_EQ("test", info.getFuncName());
}

//
// bindReturnValue()
// getReturnValueBind()
//

TEST_F(APICallInfoTests,
BindReturnValueCorrectlyBindsReturnValue) {
	APICallInfo info("test");
	info.bindReturnValue("X");
	EXPECT_EQ("X", info.getReturnValueBind());
}

TEST_F(APICallInfoTests,
WhenBindReturnValueIsCalledSeveralTimesTheLastBindIsStored) {
	APICallInfo info("test");
	info.bindReturnValue("X");
	info.bindReturnValue("Y");
	EXPECT_EQ("Y", info.getReturnValueBind());
}

TEST_F(APICallInfoTests,
ChainingBindReturnValueWorksCorrectly) {
	APICallInfo info("test");
	info.bindReturnValue("X")
		.bindReturnValue("Y");
	EXPECT_EQ("Y", info.getReturnValueBind());
}

#if DEATH_TESTS_ENABLED
TEST_F(APICallInfoTests,
WhenReturnValueIsNotBoundGetReturnValueBindResultsIntoViolatedPrecondition) {
	APICallInfo info("test");
	EXPECT_DEATH(info.getReturnValueBind(), ".*Precondition.*failed.*");
}
#endif

//
// hasBoundReturnValue()
//

TEST_F(APICallInfoTests,
WhenReturnValueIsNotBoundHasBoundReturnValueReturnsFalse) {
	APICallInfo info("test");
	EXPECT_FALSE(info.hasBoundReturnValue());
}

TEST_F(APICallInfoTests,
WhenTheReturnValueIsBoundHasBoundReturnValueReturnsTrue) {
	APICallInfo info("test");
	info.bindReturnValue("X");
	EXPECT_TRUE(info.hasBoundReturnValue());
}

//
// bindParam()
// getParamBind()
//

TEST_F(APICallInfoTests,
BindParamCorrectlyBindsParam) {
	APICallInfo info("test");
	info.bindParam(1, "X");
	EXPECT_EQ("X", info.getParamBind(1));
}

TEST_F(APICallInfoTests,
WhenParamIsBoundSeveralTimesTheLastBindIsStored) {
	APICallInfo info("test");
	info.bindParam(1, "X");
	info.bindParam(1, "Y");
	EXPECT_EQ("Y", info.getParamBind(1));
}

TEST_F(APICallInfoTests,
ChainingBindParamWorksCorrectly) {
	APICallInfo info("test");
	info.bindParam(1, "X")
		.bindParam(1, "Y");
	EXPECT_EQ("Y", info.getParamBind(1));
}

#if DEATH_TESTS_ENABLED
TEST_F(APICallInfoTests,
BindingParameterNumberZeroResultsIntoViolatedPrecondition) {
	APICallInfo info("test");
	EXPECT_DEATH(info.bindParam(0, "X"), ".*Precondition.*failed.*");
}
#endif

#if DEATH_TESTS_ENABLED
TEST_F(APICallInfoTests,
CallingGetParamBindForZeroParamResultsIntoViolatedPrecondition) {
	APICallInfo info("test");
	EXPECT_DEATH(info.getParamBind(0), ".*Precondition.*failed.*");
}
#endif

#if DEATH_TESTS_ENABLED
TEST_F(APICallInfoTests,
WhenParamIsNotBoundGetParamBindResultsIntoViolatedPrecondition) {
	APICallInfo info("test");
	EXPECT_DEATH(info.getParamBind(1), ".*Precondition.*failed.*");
}
#endif

//
// hasBoundParam()
//

TEST_F(APICallInfoTests,
WhenParamIsNotBoundHasBoundParamReturnsFalse) {
	APICallInfo info("test");
	EXPECT_FALSE(info.hasBoundParam(1));
}

TEST_F(APICallInfoTests,
WhenParamIsBoundHasBoundParamReturnsTrue) {
	APICallInfo info("test");
	info.bindParam(1, "X");
	EXPECT_TRUE(info.hasBoundParam(1));
}

//
// param_bind_begin()
// param_bind_end()
//

TEST_F(APICallInfoTests,
IteratingOverParamBindsWorksCorrectly) {
	APICallInfo info("test");
	info.bindParam(1, "X");
	info.bindParam(2, "Y");
	info.bindParam(3, "Z");
	auto i = info.param_bind_begin();
	ASSERT_TRUE(i != info.param_bind_end());
	EXPECT_EQ(1, i->first);
	EXPECT_EQ("X", i->second);
	++i;
	ASSERT_TRUE(i != info.param_bind_end());
	EXPECT_EQ(2, i->first);
	EXPECT_EQ("Y", i->second);
	++i;
	ASSERT_TRUE(i != info.param_bind_end());
	EXPECT_EQ(3, i->first);
	EXPECT_EQ("Z", i->second);
	++i;
	ASSERT_TRUE(i == info.param_bind_end());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec

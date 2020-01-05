/**
* @file tests/llvmir2hll/ir/function_type_tests.cpp
* @brief Tests for the @c function_type module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/function_type.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/void_type.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c function_type module.
*/
class FunctionTypeTests: public Test {};

//
// Return type.
//

TEST_F(FunctionTypeTests,
VoidFunctionHasReturnTypeVoid) {
	FunctionType* ft(FunctionType::create());
	EXPECT_TRUE(isa<VoidType>(ft->getRetType())) <<
		"expected VoidType, " <<
		"got `" << ft->getRetType() << "`";
}

TEST_F(FunctionTypeTests,
IntFunctionHasReturnTypeInt) {
	IntType* refRetType(IntType::create(32));
	FunctionType* ft(FunctionType::create(refRetType));
	EXPECT_TRUE(refRetType->isEqualTo(ft->getRetType())) <<
		"expected `" << refRetType << "`, " <<
		"got `" << ft->getRetType() << "`";
}

TEST_F(FunctionTypeTests,
SetReturnTypeCorrectlySetsTheType) {
	FunctionType* ft(FunctionType::create());
	ASSERT_TRUE(isa<VoidType>(ft->getRetType()));
	IntType* refRetType(IntType::create(32));
	ft->setRetType(refRetType);
	EXPECT_TRUE(refRetType->isEqualTo(ft->getRetType())) <<
		"expected `" << refRetType << "`, " <<
		"got `" << ft->getRetType() << "`";
}

//
// Variable number of arguments.
//

TEST_F(FunctionTypeTests,
FunctionIsByDefaultNotVarArg) {
	FunctionType* ft(FunctionType::create());
	EXPECT_FALSE(ft->isVarArg());
}

TEST_F(FunctionTypeTests,
FunctionThatIsSetAsVarArgIsVarArg) {
	FunctionType* ft(FunctionType::create());
	ASSERT_FALSE(ft->isVarArg());
	ft->setVarArg();
	EXPECT_TRUE(ft->isVarArg());
}

TEST_F(FunctionTypeTests,
FunctionThatIsSetAsNotVarArgAfterBeingVarArgIsNotVarArg) {
	FunctionType* ft(FunctionType::create());
	ft->setVarArg();
	ASSERT_TRUE(ft->isVarArg());
	ft->setVarArg(false);
	EXPECT_FALSE(ft->isVarArg());
}

//
// Parameters.
//

TEST_F(FunctionTypeTests,
FunctionWithoutParametersDoesNotHaveParameters) {
	FunctionType* ft(FunctionType::create());
	EXPECT_FALSE(ft->hasParams());
	EXPECT_EQ(0, ft->getNumOfParams());
	EXPECT_EQ(ft->param_begin(), ft->param_end());
}

TEST_F(FunctionTypeTests,
ParameterToFunctionWithoutParametersIsAddedCorrectly) {
	FunctionType* ft(FunctionType::create());
	ASSERT_FALSE(ft->hasParams());
	ASSERT_EQ(0, ft->getNumOfParams());
	ASSERT_FALSE(ft->hasParam(1));
	ASSERT_EQ(ft->param_begin(), ft->param_end());

	IntType* refParamType(IntType::create(32));
	ft->addParam(refParamType);
	EXPECT_TRUE(ft->hasParams());
	EXPECT_EQ(1, ft->getNumOfParams());
	EXPECT_TRUE(ft->hasParam(1));
	EXPECT_TRUE(refParamType->isEqualTo(ft->getParam(1))) <<
		"expected `" << refParamType << "`, " <<
		"got `" << ft->getParam(1) << "`";
	EXPECT_NE(ft->param_begin(), ft->param_end());
	EXPECT_TRUE(refParamType->isEqualTo(*ft->param_begin())) <<
		"expected `" << refParamType << "`, " <<
		"got `" << (*ft->param_begin()) << "`";
	EXPECT_EQ(++ft->param_begin(), ft->param_end());
}

TEST_F(FunctionTypeTests,
ParameterToFunctionWithParameterIsAddedCorrectly) {
	FunctionType* ft(FunctionType::create());
	IntType* refParam1Type(IntType::create(32));
	ft->addParam(refParam1Type);
	ASSERT_TRUE(ft->hasParams());
	ASSERT_EQ(1, ft->getNumOfParams());
	ASSERT_FALSE(ft->hasParam(2));

	IntType* refParam2Type(IntType::create(64));
	ft->addParam(refParam2Type);
	EXPECT_TRUE(ft->hasParams());
	EXPECT_EQ(2, ft->getNumOfParams());
	EXPECT_TRUE(ft->hasParam(2));
	EXPECT_TRUE(refParam2Type->isEqualTo(ft->getParam(2))) <<
		"expected `" << refParam2Type << "`, " <<
		"got `" << ft->getParam(2) << "`";
	auto i = ft->param_begin();
	// Test iteration over the parameters.
	EXPECT_NE(i, ft->param_end());
	EXPECT_TRUE(refParam1Type->isEqualTo(*i)) <<
		"expected `" << refParam1Type << "`, " <<
		"got `" << (*i) << "`";
	++i;
	EXPECT_NE(i, ft->param_end());
	EXPECT_TRUE(refParam2Type->isEqualTo(*i)) <<
		"expected `" << refParam2Type << "`, " <<
		"got `" << (*i) << "`";
	++i;
	EXPECT_EQ(i, ft->param_end());
}

//
// Equality.
//

TEST_F(FunctionTypeTests,
TwoFunctionTypesDifferingInReturnTypeAreNotEqual) {
	VoidType* f1RetType(VoidType::create());
	FunctionType* ft1(FunctionType::create(f1RetType));

	IntType* f2RetType(IntType::create(32));
	FunctionType* ft2(FunctionType::create(f2RetType));

	EXPECT_FALSE(ft1->isEqualTo(ft2));
}

TEST_F(FunctionTypeTests,
TwoFunctionTypesDifferingInVarArgAreNotEqual) {
	FunctionType* ft1(FunctionType::create());

	FunctionType* ft2(FunctionType::create());
	ft2->setVarArg();

	EXPECT_FALSE(ft1->isEqualTo(ft2));
}

TEST_F(FunctionTypeTests,
TwoFunctionTypesDifferingInNumberOfParametersAreNotEqual) {
	FunctionType* ft1(FunctionType::create());

	FunctionType* ft2(FunctionType::create());
	IntType* paramType(IntType::create(32));
	ft2->addParam(paramType);

	EXPECT_FALSE(ft1->isEqualTo(ft2));
}

TEST_F(FunctionTypeTests,
TwoFunctionTypesDifferingInTypeOfParametersAreNotEqual) {
	FunctionType* ft1(FunctionType::create());
	IntType* param1Type(IntType::create(32));
	ft1->addParam(param1Type);

	FunctionType* ft2(FunctionType::create());
	IntType* param2Type(IntType::create(64));
	ft2->addParam(param2Type);

	EXPECT_FALSE(ft1->isEqualTo(ft2));
}

TEST_F(FunctionTypeTests,
TwoFunctionTypesWithSameDataAreEqual) {
	IntType* retType(IntType::create(16));
	IntType* param1Type(IntType::create(32));
	IntType* param2Type(IntType::create(64));

	FunctionType* ft1(FunctionType::create(retType));
	ft1->addParam(param1Type);
	ft1->addParam(param2Type);
	ft1->setVarArg();

	FunctionType* ft2(FunctionType::create(retType));
	ft2->addParam(param1Type);
	ft2->addParam(param2Type);
	ft2->setVarArg();

	EXPECT_TRUE(ft1->isEqualTo(ft2));
}

//
// Cloning.
//

TEST_F(FunctionTypeTests,
CloningCreatesEqualFunctionType) {
	IntType* retType(IntType::create(16));
	IntType* param1Type(IntType::create(32));
	IntType* param2Type(IntType::create(64));
	FunctionType* ft1(FunctionType::create(retType));
	ft1->addParam(param1Type);
	ft1->addParam(param2Type);
	ft1->setVarArg();

	FunctionType* ft2(ucast<FunctionType>(ft1->clone()));

	EXPECT_TRUE(ft1->isEqualTo(ft2));
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec

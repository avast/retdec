/**
* @file tests/llvmir2hll/var_renamer/var_renamer_tests.cpp
* @brief Tests for the @c var_renamer module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/function_builder.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/ir/void_type.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/llvmir2hll/utils/ir.h"
#include "llvmir2hll/var_renamer/tests_with_var_name_gen_and_var_renamer.h"
#include "retdec/llvmir2hll/var_renamer/var_renamer.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c var_renamer module.
*/
class VarRenamerTests: public TestsWithModule {};

/**
* @brief A subclass of VarRenamer providing create().
*
* It can be used in INSTANTIATE_VAR_NAME_GEN_AND_VAR_RENAMER().
*/
class VarRenamerWithCreate: public VarRenamer {
public:
	virtual std::string getId() const override { return "renamer_with_create"; }

	static ShPtr<VarRenamer> create(ShPtr<VarNameGen> varNameGen,
			bool useDebugNames = true) {
		return ShPtr<VarRenamer>(new VarRenamerWithCreate(
			varNameGen, useDebugNames));
	}

private:
	VarRenamerWithCreate(ShPtr<VarNameGen> varNameGen, bool useDebugNames):
		VarRenamer(varNameGen, useDebugNames) {}
};

TEST_F(VarRenamerTests,
ClashingNamesEndingWithNumberAreSuffixedWithUnderscores) {
	// Set-up the module.
	//
	// int a;
	// int b;
	// int c;
	//
	// void test() {
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	module->addGlobalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	module->addGlobalVar(varB);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(32)));
	module->addGlobalVar(varC);

	// Setup the name generator so it always returns "g1".
	INSTANTIATE_VAR_NAME_GEN_AND_VAR_RENAMER(VarRenamerWithCreate, false);
	EXPECT_CALL(*varNameGenMock, getNextVarName())
		.Times(3)
		.WillOnce(Return("g1"))
		.WillOnce(Return("g1"))
		.WillOnce(Return("g1"));

	// Do the renaming.
	varRenamer->renameVars(module);

	// We expect the following output:
	//
	// int g1;
	// int g1_;
	// int g1__;
	//
	// void test() {
	// }
	//
	VarSet globalVarsSet(module->getGlobalVars());
	ASSERT_EQ(3, globalVarsSet.size());
	// We have to sort the variables to ease the checking.
	VarVector globalVarsVector(globalVarsSet.begin(), globalVarsSet.end());
	sortByName(globalVarsVector);
	ShPtr<Variable> var1(globalVarsVector[0]);
	EXPECT_EQ("g1", var1->getName());
	ShPtr<Variable> var2(globalVarsVector[1]);
	EXPECT_EQ("g1_", var2->getName());
	ShPtr<Variable> var3(globalVarsVector[2]);
	EXPECT_EQ("g1__", var3->getName());
}

TEST_F(VarRenamerTests,
ClashingNamesNotEndingWithNumberAreSuffixedWithNumbers) {
	// Set-up the module.
	//
	// int a;
	// int b;
	// int c;
	//
	// void test() {
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	module->addGlobalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	module->addGlobalVar(varB);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(32)));
	module->addGlobalVar(varC);

	// Setup the name generator so it always returns "g".
	INSTANTIATE_VAR_NAME_GEN_AND_VAR_RENAMER(VarRenamerWithCreate, false);
	EXPECT_CALL(*varNameGenMock, getNextVarName())
		.Times(3)
		.WillOnce(Return("g"))
		.WillOnce(Return("g"))
		.WillOnce(Return("g"));

	// Do the renaming.
	varRenamer->renameVars(module);

	// We expect the following output:
	//
	// int g;
	// int g2;
	// int g3;
	//
	// void test() {
	// }
	//
	VarSet globalVarsSet(module->getGlobalVars());
	ASSERT_EQ(3, globalVarsSet.size());
	// We have to sort the variables to ease the checking.
	VarVector globalVarsVector(globalVarsSet.begin(), globalVarsSet.end());
	sortByName(globalVarsVector);
	ShPtr<Variable> var1(globalVarsVector[0]);
	EXPECT_EQ("g", var1->getName());
	ShPtr<Variable> var2(globalVarsVector[1]);
	EXPECT_EQ("g2", var2->getName());
	ShPtr<Variable> var3(globalVarsVector[2]);
	EXPECT_EQ("g3", var3->getName());
}

TEST_F(VarRenamerTests,
FunctionsAreAssignedRealNamesWhenRealNamesArePresent) {
	// Set-up the module.
	//
	// void test() {
	// }
	//
	// (Already set.)

	// Setup the name generator.
	INSTANTIATE_VAR_NAME_GEN_AND_VAR_RENAMER(VarRenamerWithCreate, false);

	// Setup the config.
	EXPECT_CALL(*configMock, getRealNameForFunc("test"))
		.WillOnce(Return("real_test"));

	// Do the renaming.
	varRenamer->renameVars(module);

	// We expect the following output:
	//
	// void real_test() {
	// }
	//
	ASSERT_EQ("real_test", testFunc->getName());
}

TEST_F(VarRenamerTests,
NameUniquenessIsEnsuredEvenIfMultipleFunctionsHaveSameRealName) {
	// Set-up the module.
	//
	// void test() {
	// }
	//
	// void test2() {
	// }
	//
	ShPtr<Function> test2Func(
		FunctionBuilder("test2")
			.withRetType(VoidType::create())
			.build()
	);
	module->addFunc(test2Func);

	// Setup the name generator.
	INSTANTIATE_VAR_NAME_GEN_AND_VAR_RENAMER(VarRenamerWithCreate, false);

	// Setup the config.
	EXPECT_CALL(*configMock, getRealNameForFunc("test"))
		.WillOnce(Return("real_test"));
	EXPECT_CALL(*configMock, getRealNameForFunc("test2"))
		.WillOnce(Return("real_test"));

	// Do the renaming.
	varRenamer->renameVars(module);

	// We expect the following output:
	//
	// void real_test() {
	// }
	//
	// void real_test2() {
	// }
	//
	ASSERT_EQ("real_test", testFunc->getName());
	ASSERT_EQ("real_test2", test2Func->getName());
}

TEST_F(VarRenamerTests,
NameUniquenessIsEnsuredEvenIfFunctionHasRealNameSameAsOtherFunctionInitialName) {
	// Set-up the module.
	//
	// void test() {
	// }
	//
	// void test_other() {
	// }
	//
	ShPtr<Function> testOtherFunc(
		FunctionBuilder("test_other")
			.withRetType(VoidType::create())
			.build()
	);
	module->addFunc(testOtherFunc);

	// Setup the name generator.
	INSTANTIATE_VAR_NAME_GEN_AND_VAR_RENAMER(VarRenamerWithCreate, false);

	// Setup the config.
	EXPECT_CALL(*configMock, getRealNameForFunc("test"))
		.WillOnce(Return(""));
	EXPECT_CALL(*configMock, getRealNameForFunc("test_other"))
		.WillOnce(Return("test"));

	// Do the renaming.
	varRenamer->renameVars(module);

	// We expect the following output:
	//
	// void test() {
	// }
	//
	// void test2() {
	// }
	//
	ASSERT_EQ("test", testFunc->getName());
	ASSERT_EQ("test2", testOtherFunc->getName());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec

/**
* @file tests/llvmir2hll/analysis/alias_analysis/alias_analyses/simple_alias_analysis_tests.cpp
* @brief Tests for the @c simple_alias_analysis module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/analysis/alias_analysis/alias_analyses/simple_alias_analysis.h"
#include "retdec/llvmir2hll/ir/address_op_expr.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/deref_op_expr.h"
#include "retdec/llvmir2hll/ir/function_builder.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/pointer_type.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/ir/void_type.h"
#include "retdec/llvmir2hll/support/types.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c simple_alias_analysis module.
*/
class SimpleAliasAnalysisTests: public TestsWithModule {
protected:
	virtual void SetUp() override {
		TestsWithModule::SetUp();
		analysis = SimpleAliasAnalysis::create();
	}

protected:
	ShPtr<AliasAnalysis> analysis;
};

TEST_F(SimpleAliasAnalysisTests,
AnalysisHasNonEmptyID) {
	EXPECT_TRUE(!analysis->getId().empty()) <<
		"the analysis should have a non-empty ID";
}

TEST_F(SimpleAliasAnalysisTests,
AfterCallingInitItIsInitialized) {
	analysis->init(module);

	EXPECT_TRUE(analysis->isInitialized()) <<
		"the analysis should be initialized by now";
}

TEST_F(SimpleAliasAnalysisTests,
GlobalNonPointerVariableDoesNotPointToAnything) {
	// Set-up the module.
	//
	// int a;
	//
	// void test() {
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	module->addGlobalVar(varA);

	analysis->init(module);

	// `a` does not point to anything.
	VarSet refAMayPointTo;
	EXPECT_EQ(refAMayPointTo, analysis->mayPointTo(varA));
	EXPECT_EQ(ShPtr<Variable>(), analysis->pointsTo(varA));
}

TEST_F(SimpleAliasAnalysisTests,
LocalNonPointerVariableDoesNotPointToAnything) {
	// Set-up the module.
	//
	// void test() {
	//     int a;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	testFunc->addLocalVar(varA);
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA));
	testFunc->setBody(varDefA);

	analysis->init(module);

	// `a` does not point to anything.
	VarSet refAMayPointTo;
	EXPECT_EQ(refAMayPointTo, analysis->mayPointTo(varA));
	EXPECT_EQ(ShPtr<Variable>(), analysis->pointsTo(varA));
}

TEST_F(SimpleAliasAnalysisTests,
GlobalPointerVariableMayPointToAnythingWithAddressTaken) {
	// Set-up the module.
	//
	// int *g;
	//
	// void test() {
	//     int a;
	//     int b;
	//     g = &a;
	// }
	//
	ShPtr<Variable> varG(Variable::create("g", PointerType::create(IntType::create(16))));
	module->addGlobalVar(varG);
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	testFunc->addLocalVar(varB);
	ShPtr<AssignStmt> assignGA(AssignStmt::create(varG, AddressOpExpr::create(varA)));
	ShPtr<VarDefStmt> varDefB(VarDefStmt::create(varB, ShPtr<Expression>(), assignGA));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, ShPtr<Expression>(), varDefB));
	testFunc->setBody(varDefA);

	analysis->init(module);

	// `g` may point to `a`.
	VarSet refGMayPointTo;
	refGMayPointTo.insert(varA);
	EXPECT_EQ(refGMayPointTo, analysis->mayPointTo(varG));
	EXPECT_EQ(ShPtr<Variable>(), analysis->pointsTo(varG));
}

TEST_F(SimpleAliasAnalysisTests,
LocalPointerVariableMayPointToAnythingInFuncWithAddressTaken) {
	// Set-up the module.
	//
	// int g1;
	// int g2;
	//
	// void test() {
	//     int *p1 = &g1;
	// }
	//
	// void test2() {
	//     int *p2 = &g2;
	// }
	//
	ShPtr<Variable> varG1(Variable::create("g1", IntType::create(16)));
	module->addGlobalVar(varG1);
	ShPtr<Variable> varG2(Variable::create("g2", IntType::create(16)));
	module->addGlobalVar(varG2);
	ShPtr<Variable> varP1(Variable::create("p1", PointerType::create(IntType::create(16))));
	testFunc->addLocalVar(varP1);
	ShPtr<VarDefStmt> varDefP1(VarDefStmt::create(varP1, AddressOpExpr::create(varG1)));
	testFunc->setBody(varDefP1);

	ShPtr<Variable> varP2(Variable::create("p2", PointerType::create(IntType::create(16))));
	ShPtr<Function> testFunc2(
		FunctionBuilder("test2")
			.definitionWithBody(VarDefStmt::create(varP2, AddressOpExpr::create(varG2)))
			.withLocalVar(varP2)
			.build()
	);
	module->addFunc(testFunc2);

	analysis->init(module);

	// `p1` may point to only to `g1`, not to `g2`.
	VarSet refP1MayPointTo;
	refP1MayPointTo.insert(varG1);
	EXPECT_EQ(refP1MayPointTo, analysis->mayPointTo(varP1));
	EXPECT_EQ(ShPtr<Variable>(), analysis->pointsTo(varP1));
}

TEST_F(SimpleAliasAnalysisTests,
GlobalPointerVariableMayBeInitializedToAnAddress) {
	// Set-up the module.
	//
	// int g1;
	// int *g2 = &g1;
	//
	// void test() {
	// }
	//
	ShPtr<Variable> varG1(Variable::create("g1", IntType::create(16)));
	module->addGlobalVar(varG1);
	ShPtr<Variable> varG2(Variable::create("g2", PointerType::create(IntType::create(16))));
	module->addGlobalVar(varG2, AddressOpExpr::create(varG1));

	analysis->init(module);

	// `g2` may point to `g1`.
	VarSet refG2MayPointTo;
	refG2MayPointTo.insert(varG1);
	EXPECT_EQ(refG2MayPointTo, analysis->mayPointTo(varG2));
	EXPECT_EQ(ShPtr<Variable>(), analysis->pointsTo(varG2));
}

TEST_F(SimpleAliasAnalysisTests,
VariableWithAddressTakenMayBePointed) {
	// Set-up the module.
	//
	// int g;
	//
	// void test() {
	//     int *p = &g;
	//     return *p;
	// }
	//
	ShPtr<Variable> varG(Variable::create("g", IntType::create(32)));
	module->addGlobalVar(varG);
	ShPtr<Variable> varP(Variable::create("p", PointerType::create(
		IntType::create(32))));
	ShPtr<ReturnStmt> returnP(ReturnStmt::create(DerefOpExpr::create(varP)));
	ShPtr<VarDefStmt> varPDef(VarDefStmt::create(varP,
		AddressOpExpr::create(varG), returnP));
	testFunc->setBody(varPDef);

	analysis->init(module);

	// `g` may be pointed.
	EXPECT_TRUE(analysis->mayBePointed(varG));
}

TEST_F(SimpleAliasAnalysisTests,
VariableWhoseAddressIsNotTakenMayNotBePointed) {
	// Set-up the module.
	//
	// void test() {
	//     int a;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<VarDefStmt> varADef(VarDefStmt::create(varA));
	testFunc->setBody(varADef);

	analysis->init(module);

	// `a` may not be pointed.
	EXPECT_FALSE(analysis->mayBePointed(varA));
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec

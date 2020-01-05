/**
* @file tests/llvmir2hll/var_renamer/var_renamers/unified_var_renamer_tests.cpp
* @brief Tests for the @c unified_var_renamer module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/call_stmt.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/utils/ir.h"
#include "llvmir2hll/var_renamer/tests_with_var_name_gen_and_var_renamer.h"
#include "retdec/llvmir2hll/var_renamer/var_renamers/unified_var_renamer.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c unified_var_renamer module.
*/
class UnifiedVarRenamerTests: public TestsWithModule {};

TEST_F(UnifiedVarRenamerTests,
RenamerHasNonEmptyID) {
	INSTANTIATE_VAR_NAME_GEN_AND_VAR_RENAMER(UnifiedVarRenamer, true);

	EXPECT_TRUE(!varRenamer->getId().empty()) <<
		"the variable renamer should have a non-empty ID";
}

TEST_F(UnifiedVarRenamerTests,
NoVariablesNoRenaming) {
	// Set-up the module.
	//
	// void test() {
	// }
	//
	// (Already set.)

	// Setup the renamer.
	INSTANTIATE_VAR_NAME_GEN_AND_VAR_RENAMER(UnifiedVarRenamer, true);

	// Do the renaming.
	varRenamer->renameVars(module);

	// We expect the following output:
	//
	// void test() {
	// }
	EXPECT_EQ("test", testFunc->getName());
}

TEST_F(UnifiedVarRenamerTests,
DoNotRenameFunctionsInCalls) {
	// Set-up the module.
	//
	// void test() {
	//     test();
	// }
	//
	CallExpr* testCallExpr(CallExpr::create(testFunc->getAsVar()));
	CallStmt* testCall(CallStmt::create(testCallExpr));
	testFunc->setBody(testCall);

	// Setup the renamer.
	INSTANTIATE_VAR_NAME_GEN_AND_VAR_RENAMER(UnifiedVarRenamer, true);

	// Do the renaming.
	varRenamer->renameVars(module);

	// We expect the following output:
	//
	// void test() {
	//     test();
	// }
	//
	EXPECT_EQ("test", cast<Variable>(testCallExpr->getCalledExpr())->getName());
}

TEST_F(UnifiedVarRenamerTests,
GlobalVariablesGetCorrectlyRenamed) {
	// Set-up the module.
	//
	// int a;
	// int b;
	// int c;
	//
	// void test() {
	// }
	//
	Variable* varA(Variable::create("a", IntType::create(32)));
	module->addGlobalVar(varA);
	Variable* varB(Variable::create("b", IntType::create(32)));
	module->addGlobalVar(varB);
	Variable* varC(Variable::create("c", IntType::create(32)));
	module->addGlobalVar(varC);

	// Setup the renamer.
	INSTANTIATE_VAR_NAME_GEN_AND_VAR_RENAMER(UnifiedVarRenamer, true);

	// Do the renaming.
	varRenamer->renameVars(module);

	// We expect the following output:
	//
	// int g1;
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
	Variable* var1(globalVarsVector[0]);
	EXPECT_EQ("g1", var1->getName());
	Variable* var2(globalVarsVector[1]);
	EXPECT_EQ("g2", var2->getName());
	Variable* var3(globalVarsVector[2]);
	EXPECT_EQ("g3", var3->getName());
}

TEST_F(UnifiedVarRenamerTests,
ParametersOfFunctionDefinitionGetCorrectlyRenamed) {
	// Set-up the module.
	//
	// void test(int a, int b) {
	// }
	//
	Variable* varA(Variable::create("a", IntType::create(32)));
	testFunc->addParam(varA);
	Variable* varB(Variable::create("b", IntType::create(32)));
	testFunc->addParam(varB);

	// Setup the renamer.
	INSTANTIATE_VAR_NAME_GEN_AND_VAR_RENAMER(UnifiedVarRenamer, true);

	// Do the renaming.
	varRenamer->renameVars(module);

	// We expect the following output:
	//
	// void test(int a1, int a2) {
	// }
	//
	VarVector params(testFunc->getParams());
	ASSERT_EQ(2, params.size());
	Variable* var1(params.front());
	EXPECT_EQ("a1", var1->getName());
	Variable* var2(params.back());
	EXPECT_EQ("a2", var2->getName());
}

TEST_F(UnifiedVarRenamerTests,
ParametersOfFunctionDeclarationGetCorrectlyRenamed) {
	// Set-up the module.
	//
	// void test(int a, int b);
	//
	Variable* varA(Variable::create("a", IntType::create(32)));
	testFunc->addParam(varA);
	Variable* varB(Variable::create("b", IntType::create(32)));
	testFunc->addParam(varB);
	// testFunc is by default a definition, so we have to make it a
	// declaration.
	testFunc->convertToDeclaration();

	// Setup the renamer.
	INSTANTIATE_VAR_NAME_GEN_AND_VAR_RENAMER(UnifiedVarRenamer, true);

	// Do the renaming.
	varRenamer->renameVars(module);

	// We expect the following output:
	//
	// void test(int a1, int a2);
	//
	VarVector params(testFunc->getParams());
	ASSERT_EQ(2, params.size());
	Variable* var1(params.front());
	EXPECT_EQ("a1", var1->getName());
	Variable* var2(params.back());
	EXPECT_EQ("a2", var2->getName());
}

TEST_F(UnifiedVarRenamerTests,
FunctionLocalVariablesGetCorrectlyRenamed) {
	// Set-up the module.
	//
	// void test() {
	//     int a;
	//     int b;
	// }
	//
	Variable* varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	Variable* varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	VarDefStmt* varDefB(VarDefStmt::create(varB));
	VarDefStmt* varDefA(VarDefStmt::create(varA, Expression*(), varDefB));
	testFunc->setBody(varDefA);

	// Setup the renamer.
	INSTANTIATE_VAR_NAME_GEN_AND_VAR_RENAMER(UnifiedVarRenamer, true);

	// Do the renaming.
	varRenamer->renameVars(module);

	// We expect the following output:
	//
	// void test() {
	//     int v1;
	//     int v2;
	// }
	//
	EXPECT_EQ("v1", varDefA->getVar()->getName());
	EXPECT_EQ("v2", varDefB->getVar()->getName());
}

TEST_F(UnifiedVarRenamerTests,
VariablesWithNameFromDebugInfoAreCorrectlyRenamedWhenUsingDebugIsTrue) {
	// Set-up the module.
	//
	// int g; // from debug info
	// int h;
	//
	// void test(int p, int m) { // p has name from debug info
	//     int a;
	//     int b; // from debug info
	// }
	//
	Variable* varG(Variable::create("g", IntType::create(32)));
	module->addGlobalVar(varG);
	module->addDebugNameForVar(varG, varG->getName());
	Variable* varH(Variable::create("h", IntType::create(32)));
	module->addGlobalVar(varH);
	Variable* varP(Variable::create("p", IntType::create(32)));
	testFunc->addParam(varP);
	module->addDebugNameForVar(varP, varP->getName());
	Variable* varM(Variable::create("m", IntType::create(32)));
	testFunc->addParam(varM);
	Variable* varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	Variable* varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	module->addDebugNameForVar(varB, varB->getName());
	VarDefStmt* varDefB(VarDefStmt::create(varB));
	VarDefStmt* varDefA(VarDefStmt::create(varA, Expression*(), varDefB));
	testFunc->setBody(varDefA);

	// Setup the renamer.
	INSTANTIATE_VAR_NAME_GEN_AND_VAR_RENAMER(UnifiedVarRenamer, true);

	// Do the renaming.
	varRenamer->renameVars(module);

	// We expect the following output:
	//
	// int g;
	// int g1;
	//
	// void test(int p, int a1) {
	//     int v1;
	//     int b;
	// }
	//
	// Globals:
	VarSet globalVarsSet(module->getGlobalVars());
	ASSERT_EQ(2, globalVarsSet.size());
	// We have to sort the variables to ease the checking.
	VarVector globalVarsVector(globalVarsSet.begin(), globalVarsSet.end());
	sortByName(globalVarsVector);
	Variable* var1(globalVarsVector[0]);
	EXPECT_EQ("g", var1->getName());
	Variable* var2(globalVarsVector[1]);
	EXPECT_EQ("g1", var2->getName());
	// Parameters:
	VarVector params(testFunc->getParams());
	ASSERT_EQ(2, params.size());
	Variable* par1(params.front());
	EXPECT_EQ("p", par1->getName());
	Variable* par2(params.back());
	EXPECT_EQ("a1", par2->getName());
	// Locals:
	EXPECT_EQ("v1", varDefA->getVar()->getName());
	EXPECT_EQ("b", varDefB->getVar()->getName());
}

TEST_F(UnifiedVarRenamerTests,
WhenUseDebugNamesIsFalseDoNotUseDebugNames) {
	// Set-up the module.
	//
	// int g; // from debug info
	// int h;
	//
	// void test(int p, int m) { // p has name from debug info
	//     int a;
	//     int b; // from debug info
	// }
	//
	Variable* varG(Variable::create("g", IntType::create(32)));
	module->addGlobalVar(varG);
	module->addDebugNameForVar(varG, varG->getName());
	Variable* varH(Variable::create("h", IntType::create(32)));
	module->addGlobalVar(varH);
	Variable* varP(Variable::create("p", IntType::create(32)));
	testFunc->addParam(varP);
	module->addDebugNameForVar(varP, varP->getName());
	Variable* varM(Variable::create("m", IntType::create(32)));
	testFunc->addParam(varM);
	Variable* varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	Variable* varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	module->addDebugNameForVar(varB, varB->getName());
	VarDefStmt* varDefB(VarDefStmt::create(varB));
	VarDefStmt* varDefA(VarDefStmt::create(varA, Expression*(), varDefB));
	testFunc->setBody(varDefA);

	// Setup the renamer (do not use debug names).
	INSTANTIATE_VAR_NAME_GEN_AND_VAR_RENAMER(UnifiedVarRenamer, false);

	// Do the renaming.
	varRenamer->renameVars(module);

	// We expect the following output:
	//
	// int g1;
	// int g2;
	//
	// void test(int a1, int a2) {
	//     int v1;
	//     int v2;
	// }
	//
	// Globals:
	VarSet globalVarsSet(module->getGlobalVars());
	ASSERT_EQ(2, globalVarsSet.size());
	// We have to sort the variables to ease the checking.
	VarVector globalVarsVector(globalVarsSet.begin(), globalVarsSet.end());
	sortByName(globalVarsVector);
	Variable* var1(globalVarsVector[0]);
	EXPECT_EQ("g1", var1->getName());
	Variable* var2(globalVarsVector[1]);
	EXPECT_EQ("g2", var2->getName());
	// Parameters:
	VarVector params(testFunc->getParams());
	ASSERT_EQ(2, params.size());
	Variable* par1(params.front());
	EXPECT_EQ("a1", par1->getName());
	Variable* par2(params.back());
	EXPECT_EQ("a2", par2->getName());
	// Locals:
	EXPECT_EQ("v1", varDefA->getVar()->getName());
	EXPECT_EQ("v2", varDefB->getVar()->getName());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec

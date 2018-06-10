/**
* @file tests/llvmir2hll/var_renamer/var_renamers/readable_var_renamer_tests.cpp
* @brief Tests for the @c readable_var_renamer module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/address_op_expr.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/bit_cast_expr.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/call_stmt.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/deref_op_expr.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/for_loop_stmt.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/function_builder.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/lt_op_expr.h"
#include "retdec/llvmir2hll/ir/pointer_type.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/ir/void_type.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/utils/ir.h"
#include "llvmir2hll/var_renamer/tests_with_var_name_gen_and_var_renamer.h"
#include "retdec/llvmir2hll/var_renamer/var_renamers/readable_var_renamer.h"

using namespace ::testing;
using namespace std::string_literals;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c readable_var_renamer module.
*/
class ReadableVarRenamerTests: public TestsWithModule {
protected:
	void scenarioVarStoringTheResultOfKnownFuncIsRenamedCorrectly(
		ShPtr<Function> func, const ExprVector &args, const std::string &refVarName);
};

TEST_F(ReadableVarRenamerTests,
RenamerHasNonEmptyID) {
	INSTANTIATE_VAR_NAME_GEN_AND_VAR_RENAMER(ReadableVarRenamer, true);

	EXPECT_TRUE(!varRenamer->getId().empty()) <<
		"the variable renamer should have a non-empty ID";
}

TEST_F(ReadableVarRenamerTests,
NoVariablesNoRenaming) {
	// Set-up the module.
	//
	// void test() {
	// }
	//
	// (Already set.)

	// Setup the renamer.
	INSTANTIATE_VAR_NAME_GEN_AND_VAR_RENAMER(ReadableVarRenamer, true);

	// Do the renaming.
	varRenamer->renameVars(module);

	// We expect the following output:
	//
	// void test() {
	// }
	EXPECT_EQ("test", testFunc->getName());
}

TEST_F(ReadableVarRenamerTests,
DoNotRenameFunctionsInCalls) {
	// Set-up the module.
	//
	// void test() {
	//     test();
	// }
	//
	ShPtr<CallExpr> testCallExpr(CallExpr::create(testFunc->getAsVar()));
	ShPtr<CallStmt> testCall(CallStmt::create(testCallExpr));
	testFunc->setBody(testCall);

	// Setup the renamer.
	INSTANTIATE_VAR_NAME_GEN_AND_VAR_RENAMER(ReadableVarRenamer, true);

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

TEST_F(ReadableVarRenamerTests,
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
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	module->addGlobalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	module->addGlobalVar(varB);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(32)));
	module->addGlobalVar(varC);

	// Setup the renamer.
	INSTANTIATE_VAR_NAME_GEN_AND_VAR_RENAMER(ReadableVarRenamer, true);

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
	ShPtr<Variable> var1(globalVarsVector[0]);
	EXPECT_EQ("g1", var1->getName());
	ShPtr<Variable> var2(globalVarsVector[1]);
	EXPECT_EQ("g2", var2->getName());
	ShPtr<Variable> var3(globalVarsVector[2]);
	EXPECT_EQ("g3", var3->getName());
}

TEST_F(ReadableVarRenamerTests,
ParametersOfFunctionDefinitionGetCorrectlyRenamed) {
	// Set-up the module.
	//
	// void test(int a, int b) {
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addParam(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addParam(varB);

	// Setup the renamer.
	INSTANTIATE_VAR_NAME_GEN_AND_VAR_RENAMER(ReadableVarRenamer, true);

	// Do the renaming.
	varRenamer->renameVars(module);

	// We expect the following output:
	//
	// void test(int a1, int a2) {
	// }
	//
	VarVector params(testFunc->getParams());
	ASSERT_EQ(2, params.size());
	ShPtr<Variable> var1(params.front());
	EXPECT_EQ("a1", var1->getName());
	ShPtr<Variable> var2(params.back());
	EXPECT_EQ("a2", var2->getName());
}

TEST_F(ReadableVarRenamerTests,
ParametersOfFunctionDeclarationGetCorrectlyRenamed) {
	// Set-up the module.
	//
	// void test(int a, int b);
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addParam(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addParam(varB);
	// testFunc is by default a definition, so we have to make it a
	// declaration.
	testFunc->convertToDeclaration();

	// Setup the renamer.
	INSTANTIATE_VAR_NAME_GEN_AND_VAR_RENAMER(ReadableVarRenamer, true);

	// Do the renaming.
	varRenamer->renameVars(module);

	// We expect the following output:
	//
	// void test(int a1, int a2);
	//
	VarVector params(testFunc->getParams());
	ASSERT_EQ(2, params.size());
	ShPtr<Variable> var1(params.front());
	EXPECT_EQ("a1", var1->getName());
	ShPtr<Variable> var2(params.back());
	EXPECT_EQ("a2", var2->getName());
}

TEST_F(ReadableVarRenamerTests,
FunctionLocalVariablesGetCorrectlyRenamed) {
	// Set-up the module.
	//
	// void test() {
	//     int a;
	//     int b;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	ShPtr<VarDefStmt> varDefB(VarDefStmt::create(varB));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, ShPtr<Expression>(), varDefB));
	testFunc->setBody(varDefA);

	// Setup the renamer.
	INSTANTIATE_VAR_NAME_GEN_AND_VAR_RENAMER(ReadableVarRenamer, true);

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

TEST_F(ReadableVarRenamerTests,
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
	ShPtr<Variable> varG(Variable::create("g", IntType::create(32)));
	module->addGlobalVar(varG);
	module->addDebugNameForVar(varG, varG->getName());
	ShPtr<Variable> varH(Variable::create("h", IntType::create(32)));
	module->addGlobalVar(varH);
	ShPtr<Variable> varP(Variable::create("p", IntType::create(32)));
	testFunc->addParam(varP);
	module->addDebugNameForVar(varP, varP->getName());
	ShPtr<Variable> varM(Variable::create("m", IntType::create(32)));
	testFunc->addParam(varM);
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	module->addDebugNameForVar(varB, varB->getName());
	ShPtr<VarDefStmt> varDefB(VarDefStmt::create(varB));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, ShPtr<Expression>(), varDefB));
	testFunc->setBody(varDefA);

	// Setup the renamer.
	INSTANTIATE_VAR_NAME_GEN_AND_VAR_RENAMER(ReadableVarRenamer, true);

	// Do the renaming.
	varRenamer->renameVars(module);

	// We expect the following output:
	//
	// int g;
	// int g1;
	//
	// void test(int p, int a2) {
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
	ShPtr<Variable> var1(globalVarsVector[0]);
	EXPECT_EQ("g", var1->getName());
	ShPtr<Variable> var2(globalVarsVector[1]);
	EXPECT_EQ("g1", var2->getName());
	// Parameters:
	VarVector params(testFunc->getParams());
	ASSERT_EQ(2, params.size());
	ShPtr<Variable> par1(params.front());
	EXPECT_EQ("p", par1->getName());
	ShPtr<Variable> par2(params.back());
	EXPECT_EQ("a2", par2->getName());
	// Locals:
	EXPECT_EQ("v1", varDefA->getVar()->getName());
	EXPECT_EQ("b", varDefB->getVar()->getName());
}

TEST_F(ReadableVarRenamerTests,
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
	ShPtr<Variable> varG(Variable::create("g", IntType::create(32)));
	module->addGlobalVar(varG);
	module->addDebugNameForVar(varG, varG->getName());
	ShPtr<Variable> varH(Variable::create("h", IntType::create(32)));
	module->addGlobalVar(varH);
	ShPtr<Variable> varP(Variable::create("p", IntType::create(32)));
	testFunc->addParam(varP);
	module->addDebugNameForVar(varP, varP->getName());
	ShPtr<Variable> varM(Variable::create("m", IntType::create(32)));
	testFunc->addParam(varM);
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	module->addDebugNameForVar(varB, varB->getName());
	ShPtr<VarDefStmt> varDefB(VarDefStmt::create(varB));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, ShPtr<Expression>(), varDefB));
	testFunc->setBody(varDefA);

	// Setup the renamer (do not use debug names).
	INSTANTIATE_VAR_NAME_GEN_AND_VAR_RENAMER(ReadableVarRenamer, false);

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
	ShPtr<Variable> var1(globalVarsVector[0]);
	EXPECT_EQ("g1", var1->getName());
	ShPtr<Variable> var2(globalVarsVector[1]);
	EXPECT_EQ("g2", var2->getName());
	// Parameters:
	VarVector params(testFunc->getParams());
	ASSERT_EQ(2, params.size());
	ShPtr<Variable> par1(params.front());
	EXPECT_EQ("a1", par1->getName());
	ShPtr<Variable> par2(params.back());
	EXPECT_EQ("a2", par2->getName());
	// Locals:
	EXPECT_EQ("v1", varDefA->getVar()->getName());
	EXPECT_EQ("v2", varDefB->getVar()->getName());
}

TEST_F(ReadableVarRenamerTests,
ParametersOfMainAreProperlyRenamed) {
	// Set-up the module.
	//
	// void test() {
	// }
	//
	// int main(int a, char **b) {
	// }
	//
	ShPtr<Function> mainFunc(
		FunctionBuilder("main")
			.definitionWithEmptyBody()
			.withRetType(IntType::create(32))
			.withParam(Variable::create("a", IntType::create(32)))
			.withParam(Variable::create("b",
				PointerType::create(PointerType::create(IntType::create(8)))))
			.build()
	);
	module->addFunc(mainFunc);

	// Setup the renamer.
	INSTANTIATE_VAR_NAME_GEN_AND_VAR_RENAMER(ReadableVarRenamer, true);

	// Do the renaming.
	varRenamer->renameVars(module);

	// We expect the following output:
	//
	// void test() {
	// }
	//
	// int main(int argc, char **argv) {
	// }
	//
	VarVector params(mainFunc->getParams());
	ASSERT_EQ(2, params.size());
	ShPtr<Variable> par1(params.front());
	EXPECT_EQ("argc", par1->getName());
	ShPtr<Variable> par2(params.back());
	EXPECT_EQ("argv", par2->getName());
}

TEST_F(ReadableVarRenamerTests,
InductionVariablesOfForLoopsAreProperlyRenamed) {
	// Set-up the module.
	//
	// void test() {
	//     for (int a = 0; a < 10; a++) {
	//         for (int b = 0; b < 10; b++) {
	//         }
	//     }
	//
	//     for (int c = 0; c < 10; c++) {
	//     }
	// }
	//
	// c
	ShPtr<Variable> varC(Variable::create("c", IntType::create(32)));
	testFunc->addLocalVar(varC);
	ShPtr<ForLoopStmt> forLoopC(ForLoopStmt::create(
		varC, ConstInt::create(0, 32), LtOpExpr::create(varC, ConstInt::create(10, 32)),
		ConstInt::create(1, 32), EmptyStmt::create()));
	// b
	ShPtr<Variable> varB(Variable::create("b", IntType::create(32)));
	testFunc->addLocalVar(varB);
	ShPtr<ForLoopStmt> forLoopB(ForLoopStmt::create(
		varB, ConstInt::create(0, 32), LtOpExpr::create(varC, ConstInt::create(10, 32)),
		ConstInt::create(1, 32), EmptyStmt::create()));
	// a
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<ForLoopStmt> forLoopA(ForLoopStmt::create(
		varA, ConstInt::create(0, 32), LtOpExpr::create(varA, ConstInt::create(10, 32)),
		ConstInt::create(1, 32), forLoopB, forLoopC));
	testFunc->setBody(forLoopA);

	// Setup the renamer.
	INSTANTIATE_VAR_NAME_GEN_AND_VAR_RENAMER(ReadableVarRenamer, true);

	// Do the renaming.
	varRenamer->renameVars(module);

	// We expect the following output:
	//
	// void test() {
	//     for (int i = 0; i < 10; i++) {
	//         for (int j = 0; j < 10; j++) {
	//         }
	//     }
	//
	//     for (int i = 0; i < 10; i++) {
	//     }
	// }
	//
	EXPECT_EQ("i", forLoopA->getIndVar()->getName());
	EXPECT_EQ("j", forLoopB->getIndVar()->getName());
	EXPECT_EQ("i", forLoopC->getIndVar()->getName());
}

TEST_F(ReadableVarRenamerTests,
ReturnVariablesFromFunctionAreProperlyRenamed) {
	// Set-up the module.
	//
	// void test() {
	//     return a;
	// }
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<ReturnStmt> returnA(ReturnStmt::create(varA));
	testFunc->setBody(returnA);

	// Setup the renamer.
	INSTANTIATE_VAR_NAME_GEN_AND_VAR_RENAMER(ReadableVarRenamer, true);

	// Do the renaming.
	varRenamer->renameVars(module);

	// We expect the following output:
	//
	// void test() {
	//     return result;
	// }
	//
	EXPECT_EQ("result", cast<Variable>(returnA->getRetVal())->getName());
}

TEST_F(ReadableVarRenamerTests,
ReturnVariableFromFunctionIsNotRenamedWhenItRepresentsFunction) {
	// Set-up the module.
	//
	// void test() {
	//     return test;
	// }
	//
	auto returnA = ReturnStmt::create(testFunc->getAsVar());
	testFunc->setBody(returnA);

	// Setup the renamer.
	INSTANTIATE_VAR_NAME_GEN_AND_VAR_RENAMER(ReadableVarRenamer, true);

	// Do the renaming.
	varRenamer->renameVars(module);

	// The variable should not be renamed because it represents a function.
	EXPECT_EQ("test", cast<Variable>(returnA->getRetVal())->getName());
}

/**
* @brief Runs a test scenario where the variable storing the result of a
*        function call should be assigned the given name.
*
* @param[in] func Function that is called and whose result is stored.
* @param[in] args Arguments that should be passed to the function's call.
* @param[in] refVarName Name of the variable after renaming.
*
* @par Preconditions
*  - @a func does not have a body
*/
void ReadableVarRenamerTests::scenarioVarStoringTheResultOfKnownFuncIsRenamedCorrectly(
		ShPtr<Function> func, const ExprVector &args, const std::string &refVarName) {
	ShPtr<Function> testFunc(module->getFuncByName("test"));
	PRECONDITION(testFunc, "the module does not contain the `test` function");
	PRECONDITION(!func->getBody(), "the passed func `" << func->getName() <<
		"` has a body");

	// Set-up the module.
	//
	// void test() {
	//     return_type x = func(args);
	// }
	//
	module->addFunc(func);
	ShPtr<Variable> varX(Variable::create("x", func->getRetType()));
	testFunc->addLocalVar(varX);
	ShPtr<CallExpr> funcCallExpr(CallExpr::create(func->getAsVar(), args));
	ShPtr<AssignStmt> assignXFunc(AssignStmt::create(varX, funcCallExpr));
	testFunc->setBody(assignXFunc);

	// Setup the renamer.
	INSTANTIATE_VAR_NAME_GEN_AND_VAR_RENAMER(ReadableVarRenamer, true);
	ON_CALL(*semanticsMock, getNameOfVarStoringResult(func->getName()))
		.WillByDefault(Return(Just(std::string(refVarName))));

	// Do the renaming.
	varRenamer->renameVars(module);

	// We expect the following output:
	//
	// void test() {
	//     return_type refVarName = func(args);
	// }
	//
	EXPECT_EQ(refVarName, varX->getName());
}

TEST_F(ReadableVarRenamerTests,
VarStoringTheResultOfFopenIsNamedFile) {
	ShPtr<Function> fopenFunc(
		FunctionBuilder("fopen")
			.withRetType(IntType::create(32))
			.build()
	);

	SCOPED_TRACE("file = fopen();");
	scenarioVarStoringTheResultOfKnownFuncIsRenamedCorrectly(
		fopenFunc, ExprVector(), "file");
}

TEST_F(ReadableVarRenamerTests,
VarStoringTheResultOfGetcIsNamedC) {
	ShPtr<Function> getcFunc(
		FunctionBuilder("getc")
			.withRetType(IntType::create(32))
			.build()
	);

	SCOPED_TRACE("c = getc();");
	scenarioVarStoringTheResultOfKnownFuncIsRenamedCorrectly(
		getcFunc, ExprVector(), "c");
}

TEST_F(ReadableVarRenamerTests,
VarStoringTheResultOfFgetcIsNamedC) {
	ShPtr<Function> fgetcFunc(
		FunctionBuilder("fgetc")
			.withRetType(IntType::create(32))
			.build()
	);

	SCOPED_TRACE("c = fgetc();");
	scenarioVarStoringTheResultOfKnownFuncIsRenamedCorrectly(
		fgetcFunc, ExprVector(), "c");
}

TEST_F(ReadableVarRenamerTests,
VarStoringTheResultOfGetcharIsNamedC) {
	ShPtr<Function> getcharFunc(
		FunctionBuilder("getchar")
			.withRetType(IntType::create(32))
			.build()
	);

	SCOPED_TRACE("c = getchar();");
	scenarioVarStoringTheResultOfKnownFuncIsRenamedCorrectly(
		getcharFunc, ExprVector(), "c");
}

TEST_F(ReadableVarRenamerTests,
VarStoringTheResultOfSocketIsNamedSockId) {
	ShPtr<Function> socketFunc(
		FunctionBuilder("socket")
			.withRetType(IntType::create(32))
			.build()
	);

	SCOPED_TRACE("sock_id = socket();");
	scenarioVarStoringTheResultOfKnownFuncIsRenamedCorrectly(
		socketFunc, ExprVector(), "sock_id");
}

TEST_F(ReadableVarRenamerTests,
VarStoringTheResultOfFunctionDefinitionIsNotGivenSpecialName) {
	// Set-up the module.
	//
	// int getchar() {} // definition
	//
	// void test() {
	//     int x = getchar();
	// }
	//
	ShPtr<Function> getcharFunc(
		FunctionBuilder("getchar")
			.definitionWithEmptyBody()
			.withRetType(IntType::create(32))
			.build()
	);
	module->addFunc(getcharFunc);
	ShPtr<Variable> varX(Variable::create("x", IntType::create(32)));
	testFunc->addLocalVar(varX);
	ShPtr<CallExpr> funcCallExpr(CallExpr::create(getcharFunc->getAsVar()));
	ShPtr<AssignStmt> assignXFunc(AssignStmt::create(varX, funcCallExpr));
	testFunc->setBody(assignXFunc);

	// Setup the renamer.
	INSTANTIATE_VAR_NAME_GEN_AND_VAR_RENAMER(ReadableVarRenamer, true);

	// Do the renaming.
	varRenamer->renameVars(module);

	// Check that the variable hasn't been given a special name.
	EXPECT_EQ("v1", varX->getName());
}

TEST_F(ReadableVarRenamerTests,
VarStoringTheResultOfNotWellKnownFunctionIsNotGivenSpecialName) {
	// Set-up the module.
	//
	// int unusual_func() {} // definition
	//
	// void test() {
	//     int x = unusual_func();
	// }
	//
	ShPtr<Function> unusualFunc(
		FunctionBuilder("unusual")
			.definitionWithEmptyBody()
			.withRetType(IntType::create(32))
			.build()
	);
	module->addFunc(unusualFunc);
	ShPtr<Variable> varX(Variable::create("x", IntType::create(32)));
	testFunc->addLocalVar(varX);
	ShPtr<CallExpr> funcCallExpr(CallExpr::create(unusualFunc->getAsVar()));
	ShPtr<AssignStmt> assignXFunc(AssignStmt::create(varX, funcCallExpr));
	testFunc->setBody(assignXFunc);

	// Setup the renamer.
	INSTANTIATE_VAR_NAME_GEN_AND_VAR_RENAMER(ReadableVarRenamer, true);

	// Do the renaming.
	varRenamer->renameVars(module);

	// Check that the variable hasn't been given a special name.
	EXPECT_EQ("v1", varX->getName());
}

TEST_F(ReadableVarRenamerTests,
VariablesPassedAsArgumentsToWellKnownFunctionAreGivenSpecialNames) {
	// Set-up the module.
	//
	// int fopen(p1, p2); // declaration of a well-known function
	//
	// void test() {
	//     fopen(v1, v2);
	// }
	//
	ShPtr<Function> fopenFunc(
		FunctionBuilder("fopen")
			.withRetType(IntType::create(32))
			.withParam(Variable::create("p1", IntType::create(32)))
			.withParam(Variable::create("p2", IntType::create(32)))
			.build()
	);
	module->addFunc(fopenFunc);
	ShPtr<Variable> var1(Variable::create("v1", IntType::create(32)));
	testFunc->addLocalVar(var1);
	ShPtr<Variable> var2(Variable::create("v2", IntType::create(32)));
	testFunc->addLocalVar(var2);
	ExprVector fopenCallArgs;
	fopenCallArgs.push_back(var1);
	fopenCallArgs.push_back(var2);
	ShPtr<CallExpr> fopenCallExpr(CallExpr::create(fopenFunc->getAsVar(),
		fopenCallArgs));
	ShPtr<CallStmt> fopenCallStmt(CallStmt::create(fopenCallExpr));
	testFunc->setBody(fopenCallStmt);

	// Setup the renamer.
	INSTANTIATE_VAR_NAME_GEN_AND_VAR_RENAMER(ReadableVarRenamer, true);
	ON_CALL(*semanticsMock, getNameOfParam("fopen", 1))
		.WillByDefault(Return(Just("file_path"s)));
	ON_CALL(*semanticsMock, getNameOfParam("fopen", 2))
		.WillByDefault(Return(Just("mode"s)));

	// Do the renaming.
	varRenamer->renameVars(module);

	// Check that the variables have been given special names.
	EXPECT_EQ("file_path", var1->getName());
	EXPECT_EQ("mode", var2->getName());
}

TEST_F(ReadableVarRenamerTests,
DereferenceAndAddressAndCastsAreIgnoredWhenNamingArgumentsOfWellKnownFunctions) {
	// Set-up the module.
	//
	// int isdigit(i); // declaration of a well-known function
	//
	// void test() {
	//     getchar(*((int *)&x));
	// }
	//
	auto isdigitFunc = FunctionBuilder("isdigit")
		.withRetType(IntType::create(32))
		.withParam(Variable::create("i", IntType::create(32)))
		.build();
	module->addFunc(isdigitFunc);
	auto varX = Variable::create("x", IntType::create(32));
	testFunc->addLocalVar(varX);
	ExprVector isdigitCallArgs{
		DerefOpExpr::create(
			BitCastExpr::create(
				AddressOpExpr::create(varX),
				PointerType::create(IntType::create(32))
			)
		)
	};
	auto isdigitCallExpr = CallExpr::create(
		isdigitFunc->getAsVar(),
		isdigitCallArgs
	);
	auto isdigitCallStmt = CallStmt::create(isdigitCallExpr);
	testFunc->setBody(isdigitCallStmt);

	// Setup the renamer.
	INSTANTIATE_VAR_NAME_GEN_AND_VAR_RENAMER(ReadableVarRenamer, true);
	ON_CALL(*semanticsMock, getNameOfParam("isdigit", 1))
		.WillByDefault(Return(Just("c"s)));

	// Do the renaming.
	varRenamer->renameVars(module);

	// Check that the variable has been given a special name.
	EXPECT_EQ("c", varX->getName());
}

TEST_F(ReadableVarRenamerTests,
VariablePassedAsArgumentToWellKnownFunctionIsNotRenamedWhenItIsFunction) {
	// Set-up the module.
	//
	// int fopen(p1, p2); // declaration of a well-known function
	//
	// void test() {
	//     fopen(v1, test); // test is the testing function
	// }
	//
	ShPtr<Function> fopenFunc(
		FunctionBuilder("fopen")
			.withRetType(IntType::create(32))
			.withParam(Variable::create("p1", IntType::create(32)))
			.withParam(Variable::create("p2", IntType::create(32)))
			.build()
	);
	module->addFunc(fopenFunc);
	ShPtr<Variable> var1(Variable::create("v1", IntType::create(32)));
	testFunc->addLocalVar(var1);
	ExprVector fopenCallArgs;
	fopenCallArgs.push_back(var1);
	fopenCallArgs.push_back(testFunc->getAsVar());
	ShPtr<CallExpr> fopenCallExpr(CallExpr::create(fopenFunc->getAsVar(),
		fopenCallArgs));
	ShPtr<CallStmt> fopenCallStmt(CallStmt::create(fopenCallExpr));
	testFunc->setBody(fopenCallStmt);

	// Setup the renamer.
	INSTANTIATE_VAR_NAME_GEN_AND_VAR_RENAMER(ReadableVarRenamer, true);
	ON_CALL(*semanticsMock, getNameOfParam("fopen", 1))
		.WillByDefault(Return(Nothing<std::string>()));
	ON_CALL(*semanticsMock, getNameOfParam("fopen", 2))
		.WillByDefault(Return(Just("mode"s)));

	// Do the renaming.
	varRenamer->renameVars(module);

	// Check that the testing function was not renamed.
	EXPECT_EQ("test", testFunc->getName());
}

TEST_F(ReadableVarRenamerTests,
GlobalVarPassedAsArgOfWellKnownFunctionIsNotGivenSpecialName) {
	// Set-up the module.
	//
	// int x;
	//
	// void putchar(p1); // declaration of a well-known function
	//
	// void test() {
	//     putchar(x);
	// }
	//
	ShPtr<Variable> varX(Variable::create("x", IntType::create(32)));
	module->addGlobalVar(varX);
	// putchar:
	ShPtr<Function> putcharFunc(
		FunctionBuilder("putchar")
			.withParam(Variable::create("p1", IntType::create(32)))
			.build()
	);
	module->addFunc(putcharFunc);
	// test:
	ExprVector putcharArgs;
	putcharArgs.push_back(varX);
	ShPtr<CallExpr> putcharCallExpr(CallExpr::create(
		putcharFunc->getAsVar(), putcharArgs));
	ShPtr<CallStmt> putcharCall(CallStmt::create(putcharCallExpr));
	testFunc->setBody(putcharCall);

	// Setup the renamer.
	INSTANTIATE_VAR_NAME_GEN_AND_VAR_RENAMER(ReadableVarRenamer, true);
	ON_CALL(*semanticsMock, getNameOfParam(putcharFunc->getName(), 1))
		.WillByDefault(Return(Just("c"s)));

	// Do the renaming.
	varRenamer->renameVars(module);

	// Check that the variable hasn't been given a special name.
	EXPECT_EQ("g1", varX->getName());
}

TEST_F(ReadableVarRenamerTests,
VarPassedAsArgOfNotWellKnownFunctionIsNotGivenSpecialName) {
	// Set-up the module.
	//
	// int unusual_func(p1); // declaration of a not-well-known function
	//
	// void test() {
	//     unusual_func(v1);
	// }
	//
	ShPtr<Function> unusualFunc(
		FunctionBuilder("unusual")
			.withRetType(IntType::create(32))
			.withParam(Variable::create("p1", IntType::create(32)))
			.build()
	);
	module->addFunc(unusualFunc);
	ShPtr<Variable> var1(Variable::create("v1", IntType::create(32)));
	testFunc->addLocalVar(var1);
	ExprVector unusualCallArgs;
	unusualCallArgs.push_back(var1);
	ShPtr<CallExpr> unusualCallExpr(CallExpr::create(unusualFunc->getAsVar(),
		unusualCallArgs));
	ShPtr<CallStmt> unusualCallStmt(CallStmt::create(unusualCallExpr));
	testFunc->setBody(unusualCallStmt);

	// Setup the renamer.
	INSTANTIATE_VAR_NAME_GEN_AND_VAR_RENAMER(ReadableVarRenamer, true);
	ON_CALL(*semanticsMock, getNameOfParam("unusual", 1))
		.WillByDefault(Return(Nothing<std::string>()));

	// Do the renaming.
	varRenamer->renameVars(module);

	// Check that the variable hasn't been given a special name.
	EXPECT_EQ("v1", var1->getName());
}

TEST_F(ReadableVarRenamerTests,
VarPassedAsArgOfFunctionDefinitionIsNotGivenSpecialName) {
	// Set-up the module.
	//
	// int fopen(p1, p2) {} // definition
	//
	// void test() {
	//     fopen(v1, v2);
	// }
	//
	ShPtr<Function> fopenFunc(
		FunctionBuilder("putchar")
			.definitionWithEmptyBody()
			.withParam(Variable::create("p1", IntType::create(32)))
			.withParam(Variable::create("p2", IntType::create(32)))
			.build()
	);
	module->addFunc(fopenFunc);
	ShPtr<Variable> var1(Variable::create("v1", IntType::create(32)));
	testFunc->addLocalVar(var1);
	ShPtr<Variable> var2(Variable::create("v2", IntType::create(32)));
	testFunc->addLocalVar(var2);
	ExprVector fopenCallArgs;
	fopenCallArgs.push_back(var1);
	fopenCallArgs.push_back(var2);
	ShPtr<CallExpr> fopenCallExpr(CallExpr::create(fopenFunc->getAsVar(),
		fopenCallArgs));
	ShPtr<CallStmt> fopenCallStmt(CallStmt::create(fopenCallExpr));
	testFunc->setBody(fopenCallStmt);

	// Setup the renamer.
	INSTANTIATE_VAR_NAME_GEN_AND_VAR_RENAMER(ReadableVarRenamer, true);

	// Do the renaming.
	varRenamer->renameVars(module);

	// Check that the variables haven't been given special names.
	EXPECT_EQ("v1", var1->getName());
	EXPECT_EQ("v2", var2->getName());
}

TEST_F(ReadableVarRenamerTests,
VarStoringTheResultOfKnownFuncIsRenamedBeforeVarPassedAsArgument) {
	// Set-up the module.
	//
	// int getchar();   // declaration of a well-known function
	// void putchar(p1); // declaration of a well-known function
	//
	// void test() {
	//     int x = getchar();
	//     putchar(x);
	// }
	//
	// getchar:
	ShPtr<Function> getcharFunc(
		FunctionBuilder("getchar")
			.withRetType(IntType::create(32))
			.build()
	);
	module->addFunc(getcharFunc);
	// putchar:
	ShPtr<Function> putcharFunc(
		FunctionBuilder("putchar")
			.withParam(Variable::create("p1", IntType::create(32)))
			.build()
	);
	module->addFunc(putcharFunc);
	// test:
	ShPtr<Variable> varX(Variable::create("x", IntType::create(32)));
	testFunc->addLocalVar(varX);
	ExprVector putcharArgs;
	putcharArgs.push_back(varX);
	ShPtr<CallExpr> putcharCallExpr(CallExpr::create(
		putcharFunc->getAsVar(), putcharArgs));
	ShPtr<CallStmt> putcharCall(CallStmt::create(putcharCallExpr));
	ShPtr<CallExpr> getcharCallExpr(CallExpr::create(
		getcharFunc->getAsVar()));
	ShPtr<AssignStmt> assignXGetcharCall(AssignStmt::create(
		varX, getcharCallExpr, putcharCall));
	testFunc->setBody(assignXGetcharCall);

	// Setup the renamer.
	std::string expectedVarXNameAfterRename("c");
	INSTANTIATE_VAR_NAME_GEN_AND_VAR_RENAMER(ReadableVarRenamer, true);
	ON_CALL(*semanticsMock, getNameOfVarStoringResult(getcharFunc->getName()))
		.WillByDefault(Return(Just(expectedVarXNameAfterRename)));
	ON_CALL(*semanticsMock, getNameOfParam(putcharFunc->getName(), 1))
		.WillByDefault(Return(Just("d"s)));

	// Do the renaming.
	varRenamer->renameVars(module);

	// Check that varX is named by using the getNameOfVarStoringResult()
	// semantics before using the getNameOfParam() semantics.
	EXPECT_EQ(expectedVarXNameAfterRename, varX->getName());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec

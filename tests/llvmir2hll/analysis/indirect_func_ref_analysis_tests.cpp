/**
* @file tests/llvmir2hll/analysis/indirect_func_ref_analysis_tests.cpp
* @brief Tests for the @c indirect_func_ref_analysis module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/analysis/indirect_func_ref_analysis.h"
#include "retdec/llvmir2hll/ir/bit_cast_expr.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/call_stmt.h"
#include "retdec/llvmir2hll/ir/function_builder.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/utils/container.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c indirect_func_ref_analysis module.
*/
class IndirectFuncRefAnalysisTests: public TestsWithModule {
protected:
	ShPtr<Function> addFooFuncToModule();

	void scenarioGivenIndirectlyReferencedFuncsAreFound(const FuncSet &expectedFuncs);
	void scenarioNoIndirectlyReferencedFuncsAreFound();
};

/**
* @brief Inserts a <tt>int foo()</tt> function declaration into the module and
*        returns it.
*/
ShPtr<Function> IndirectFuncRefAnalysisTests::addFooFuncToModule() {
	ShPtr<Function> fooFunc(
		FunctionBuilder("foo")
			.withRetType(IntType::create(32))
			.build()
	);
	module->addFunc(fooFunc);
	return fooFunc;
}

/**
* @brief Verifies that the given functions are found as indirectly referenced
*        in the module.
*/
void IndirectFuncRefAnalysisTests::scenarioGivenIndirectlyReferencedFuncsAreFound(
		const FuncSet &expectedFuncs) {
	// getIndirectlyReferencedFuncs()
	FuncSet funcs(IndirectFuncRefAnalysis::getIndirectlyReferencedFuncs(module));
	EXPECT_EQ(expectedFuncs, funcs);

	// isIndirectlyReferenced()
	for (const auto &func : expectedFuncs) {
		EXPECT_TRUE(IndirectFuncRefAnalysis::isIndirectlyReferenced(module, func))
			<< "expected `" << func->getName() << "` "
			<< "to be considered as indirectly referenced";
	}
}

/**
* @brief Verifies that no functions are found as indirectly referenced in the
*        module.
*/
void IndirectFuncRefAnalysisTests::scenarioNoIndirectlyReferencedFuncsAreFound() {
	scenarioGivenIndirectlyReferencedFuncsAreFound(FuncSet());
}

TEST_F(IndirectFuncRefAnalysisTests,
ThereAreNoIndirectlyReferencedFuncsWhenThereAreNoFuncReferences) {
	// Set-up the module.
	//
	// void test() {}
	//
	// -

	SCOPED_TRACE("");
	scenarioNoIndirectlyReferencedFuncsAreFound();
}

TEST_F(IndirectFuncRefAnalysisTests,
ThereAreNoIndirectlyReferencedFuncsWhenOnlyDirectCallsAreMade) {
	// Set-up the module.
	//
	// int foo();
	//
	// void test() {
	//     int a = foo();
	//     foo();
	// }
	//
	ShPtr<Function> fooFunc(addFooFuncToModule());
	ShPtr<CallExpr> fooCall(CallExpr::create(fooFunc->getAsVar()));
	ShPtr<CallStmt> fooCallStmt(CallStmt::create(fooCall));
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA,
		ucast<CallExpr>(fooCall->clone()), fooCallStmt));
	testFunc->addLocalVar(varA);
	testFunc->setBody(varDefA);

	SCOPED_TRACE("");
	scenarioNoIndirectlyReferencedFuncsAreFound();
}

TEST_F(IndirectFuncRefAnalysisTests,
FunctionStoredIntoVariableIsConsideredAsIndirectlyReferenced) {
	// Set-up the module.
	//
	// int foo();
	//
	// void test() {
	//     int a = foo; // The type mismatch does not matter.
	// }
	//
	ShPtr<Function> fooFunc(addFooFuncToModule());
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, fooFunc->getAsVar()));
	testFunc->setBody(varDefA);

	FuncSet expectedFuncs;
	expectedFuncs.insert(fooFunc);
	SCOPED_TRACE("");
	scenarioGivenIndirectlyReferencedFuncsAreFound(expectedFuncs);
}

TEST_F(IndirectFuncRefAnalysisTests,
LocalVariableWithSameNameAsFunctionIsNotMistakenForFunction) {
	// Set-up the module.
	//
	// int foo();
	//
	// void test() {
	//     int foo;
	//     int a = foo;
	// }
	//
	ShPtr<Function> fooFunc(addFooFuncToModule());
	ShPtr<Variable> varFoo(Variable::create("foo", IntType::create(32)));
	testFunc->addLocalVar(varFoo);
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, varFoo));
	testFunc->addLocalVar(varA);
	ShPtr<VarDefStmt> varDefFoo(VarDefStmt::create(varFoo,
		ShPtr<Expression>(), varDefA));
	testFunc->setBody(varDefFoo);

	SCOPED_TRACE("");
	scenarioNoIndirectlyReferencedFuncsAreFound();
}

TEST_F(IndirectFuncRefAnalysisTests,
ParameterWithSameNameAsFunctionIsNotMistakenForFunction) {
	// Set-up the module.
	//
	// int foo();
	//
	// void test(int foo) {
	//     int a = foo;
	// }
	//
	ShPtr<Function> fooFunc(addFooFuncToModule());
	ShPtr<Variable> varFoo(Variable::create("foo", IntType::create(32)));
	testFunc->addParam(varFoo);
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, varFoo));
	testFunc->addLocalVar(varA);
	testFunc->setBody(varDefA);

	SCOPED_TRACE("");
	scenarioNoIndirectlyReferencedFuncsAreFound();
}

TEST_F(IndirectFuncRefAnalysisTests,
FunctionCalledAfterCastIsConsideredAsIndirectlyCalled) {
	// Set-up the module.
	//
	// int foo();
	//
	// void test() {
	//     int a = ((int)foo)(); // The type mismatch does not matter.
	// }
	//
	ShPtr<Function> fooFunc(addFooFuncToModule());
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	testFunc->addLocalVar(varA);
	ShPtr<BitCastExpr> castedFoo(BitCastExpr::create(fooFunc->getAsVar(),
		IntType::create(32)));
	ShPtr<CallExpr> fooCall(CallExpr::create(castedFoo));
	ShPtr<VarDefStmt> varDefA(VarDefStmt::create(varA, fooCall));
	testFunc->setBody(varDefA);

	FuncSet expectedFuncs;
	expectedFuncs.insert(fooFunc);
	SCOPED_TRACE("");
	scenarioGivenIndirectlyReferencedFuncsAreFound(expectedFuncs);
}

#if DEATH_TESTS_ENABLED
TEST_F(IndirectFuncRefAnalysisTests,
PreconditionFailsWhenModuleIsNull) {
	EXPECT_DEATH(IndirectFuncRefAnalysis::getIndirectlyReferencedFuncs(
		ShPtr<Module>()), ".*getIndirectlyReferencedFuncs.*Precondition.*failed.*");
}
#endif

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec

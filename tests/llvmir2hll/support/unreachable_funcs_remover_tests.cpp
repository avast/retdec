/**
* @file tests/llvmir2hll/support/unreachable_funcs_remover_tests.cpp
* @brief Tests for the @c unreachable_funcs_remover module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/call_stmt.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/ir/void_type.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/llvmir2hll/support/unreachable_funcs_remover.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c unreachable_funcs_remover module.
*/
class UnreachableFuncsRemoverTests: public TestsWithModule {
private:
	virtual void SetUp() override {
		TestsWithModule::SetUp();

		// We want to start with 'main", not with "test".
		testFunc->setName("main");
	}
};

TEST_F(UnreachableFuncsRemoverTests,
DoNotRemoveAnythingIfThereIsJustTheMainFunction) {
	// Set-up the module.
	//
	// void main() {}
	//

	// Perform the removal.
	FuncVector removedFuncs(UnreachableFuncsRemover::removeFuncs(module, "main"));

	// Check that the output is correct.
	EXPECT_TRUE(removedFuncs.empty());
	EXPECT_TRUE(module->getFuncByName("main"));
}

TEST_F(UnreachableFuncsRemoverTests,
RemoveFunctionDefinitionsNotCalledFromMain) {
	// Set-up the module.
	//
	// void notCalled1() {}
	// void notCalled2() {}
	// void main() {}
	//
	addFuncDef("notCalled1");
	addFuncDef("notCalled2");

	// The reference results have to be prepared before the elimination (after
	// that, the functions are no longer in the module).
	FuncVector refRemovedFuncs;
	refRemovedFuncs.push_back(module->getFuncByName("notCalled1"));
	refRemovedFuncs.push_back(module->getFuncByName("notCalled2"));

	// Perform the removal.
	FuncVector removedFuncs(UnreachableFuncsRemover::removeFuncs(module, "main"));

	// Check that the output is correct.
	EXPECT_EQ(refRemovedFuncs, removedFuncs);
	EXPECT_TRUE(module->getFuncByName("main"));
	EXPECT_FALSE(module->getFuncByName("notCalled1"));
	EXPECT_FALSE(module->getFuncByName("notCalled2"));
}

TEST_F(UnreachableFuncsRemoverTests,
RemoveFunctionDefinitionNotCalledFromMainCustomMainFunc) {
	// Set-up the module.
	//
	// void notCalled() {}
	// void main() {}
	//
	addFuncDef("notCalled");

	// The reference results have to be prepared before the elimination (after
	// that, the functions are no longer in the module).
	FuncVector refRemovedFuncs;
	refRemovedFuncs.push_back(module->getFuncByName("main"));

	// Perform the removal.
	FuncVector removedFuncs(UnreachableFuncsRemover::removeFuncs(module, "notCalled")); // <-- custom name

	// Check that the output is correct.
	EXPECT_EQ(refRemovedFuncs, removedFuncs);
	EXPECT_TRUE(module->getFuncByName("notCalled"));
	EXPECT_FALSE(module->getFuncByName("main"));
}

TEST_F(UnreachableFuncsRemoverTests,
DoNotRemoveFunctionDeclarationsEvenIfNotCalledFromMain) {
	// Set-up the module.
	//
	// void notCalledDecl1();
	// void notCalledDecl2();
	// void main() {}
	//
	addFuncDecl("notCalledDecl1");
	addFuncDecl("notCalledDecl2");

	// Perform the removal.
	FuncVector removedFuncs(UnreachableFuncsRemover::removeFuncs(module, "main"));

	// Check that the output is correct.
	EXPECT_TRUE(removedFuncs.empty());
	EXPECT_TRUE(module->getFuncByName("main"));
	EXPECT_TRUE(module->getFuncByName("notCalledDecl1"));
	EXPECT_TRUE(module->getFuncByName("notCalledDecl2"));
}

TEST_F(UnreachableFuncsRemoverTests,
DoNotRemoveFunctionDefinitionsCalledDirectlyFromMain) {
	// Set-up the module.
	//
	// void notCalled() {}
	// void called1() {}
	// void called2() {}
	//
	// void main() {
	//     called1();
	//     called2();
	// }
	//
	addFuncDef("notCalled");
	addFuncDef("called1");
	addFuncDef("called2");
	addCall("main", "called1");
	addCall("main", "called2");

	// The reference results have to be prepared before the elimination (after
	// that, the functions are no longer in the module).
	FuncVector refRemovedFuncs;
	refRemovedFuncs.push_back(module->getFuncByName("notCalled"));

	// Perform the removal.
	FuncVector removedFuncs(UnreachableFuncsRemover::removeFuncs(module, "main"));

	// Check that the output is correct.
	EXPECT_EQ(refRemovedFuncs, removedFuncs);
	EXPECT_TRUE(module->getFuncByName("main"));
	EXPECT_FALSE(module->getFuncByName("notCalled"));
	EXPECT_TRUE(module->getFuncByName("called1"));
	EXPECT_TRUE(module->getFuncByName("called2"));
}

TEST_F(UnreachableFuncsRemoverTests,
DoNotRemoveFunctionDefinitionsCalledFromFunctionThatIsCalledFromMain) {
	// Set-up the module.
	//
	// void notCalled() {}
	// void called1() {
	//     called2();
	// }
	// void called2() {}
	//
	// void main() {
	//     called1();
	// }
	//
	addFuncDef("notCalled");
	addFuncDef("called1");
	addFuncDef("called2");
	addCall("main", "called1");
	addCall("called1", "called2");

	// The reference results have to be prepared before the elimination (after
	// that, the functions are no longer in the module).
	FuncVector refRemovedFuncs;
	refRemovedFuncs.push_back(module->getFuncByName("notCalled"));

	// Perform the removal.
	FuncVector removedFuncs(UnreachableFuncsRemover::removeFuncs(module, "main"));

	// Check that the output is correct.
	EXPECT_EQ(refRemovedFuncs, removedFuncs);
	EXPECT_TRUE(module->getFuncByName("main"));
	EXPECT_FALSE(module->getFuncByName("notCalled"));
	EXPECT_TRUE(module->getFuncByName("called1"));
	EXPECT_TRUE(module->getFuncByName("called2"));
}

TEST_F(UnreachableFuncsRemoverTests,
DoNotDoAnythingIfThereIsNoMainFunction) {
	// Set-up the module.
	//
	// void notCalled1() {}
	// void notCalled2() {}
	//
	module->removeFunc(testFunc); // testFunc == main
	addFuncDef("notCalled1");
	addFuncDef("notCalled2");

	// The reference results have to be prepared before the elimination (after
	// that, the functions are no longer in the module).
	FuncVector refRemovedFuncs;

	// Perform the removal.
	FuncVector removedFuncs(UnreachableFuncsRemover::removeFuncs(module, "main"));

	// Check that the output is correct.
	EXPECT_EQ(refRemovedFuncs, removedFuncs);
	EXPECT_TRUE(module->getFuncByName("notCalled1"));
	EXPECT_TRUE(module->getFuncByName("notCalled2"));
}

TEST_F(UnreachableFuncsRemoverTests,
DoNotRemoveFunctionsThatMayBeCalledIndirectly) {
	// Set-up the module.
	//
	// void indCalled() {}
	//
	// void main() {
	//     void (*p)() = indCalled;
	//     p();
	// }
	//
	ShPtr<Function> indCalledFunc(addFuncDef("indCalled"));
	// The type of p is irrelevant, so we use an integer.
	ShPtr<Variable> varP(Variable::create("p", IntType::create(32)));
	ShPtr<CallStmt> callP(CallStmt::create(CallExpr::create(varP)));
	ShPtr<VarDefStmt> varDefP(VarDefStmt::create(varP, indCalledFunc->getAsVar(), callP));
	testFunc->setBody(varDefP);

	// The reference results have to be prepared before the elimination (after
	// that, the functions are no longer in the module).
	FuncVector refRemovedFuncs;

	// Perform the removal.
	FuncVector removedFuncs(UnreachableFuncsRemover::removeFuncs(module, "main"));

	// Check that the output is correct.
	EXPECT_EQ(refRemovedFuncs, removedFuncs);
	EXPECT_TRUE(module->getFuncByName("main"));
	EXPECT_TRUE(module->getFuncByName("indCalled"));
}

TEST_F(UnreachableFuncsRemoverTests,
DoNotRemoveFunctionsCalledDirectlyFromIndirectCalls) {
	// Set-up the module.
	//
	// void dirCalled() {}
	// void indirCalled() {
	//     dirCalled();
	// }
	//
	// void main() {
	//     void (*p)() = indirCalled;
	//     p();
	// }
	//
	ShPtr<Function> dirCalledFunc(addFuncDef("dirCalled"));
	ShPtr<Function> indirCalledFunc(addFuncDef("indirCalled"));
	addCall("indirCalled", "dirCalled");
	// The type of p is irrelevant, so we use an integer.
	ShPtr<Variable> varP(Variable::create("p", IntType::create(32)));
	ShPtr<CallStmt> callP(CallStmt::create(CallExpr::create(varP)));
	ShPtr<VarDefStmt> varDefP(VarDefStmt::create(varP,
		indirCalledFunc->getAsVar(), callP));
	testFunc->setBody(varDefP);

	// The reference results have to be prepared before the elimination (after
	// that, the functions are no longer in the module).
	FuncVector refRemovedFuncs;

	// Perform the removal.
	FuncVector removedFuncs(UnreachableFuncsRemover::removeFuncs(module, "main"));

	// Check that the output is correct.
	EXPECT_EQ(refRemovedFuncs, removedFuncs);
	EXPECT_TRUE(module->getFuncByName("main"));
	EXPECT_TRUE(module->getFuncByName("dirCalled"));
	EXPECT_TRUE(module->getFuncByName("indirCalled"));
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec

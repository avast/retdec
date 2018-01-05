/**
* @file tests/llvmir2hll/analysis/written_into_globals_visitor_tests.cpp
* @brief Tests for the @c written_into_globals_visitor module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/analysis/written_into_globals_visitor.h"
#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/array_index_op_expr.h"
#include "retdec/llvmir2hll/ir/array_type.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/deref_op_expr.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/for_loop_stmt.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/lt_op_expr.h"
#include "retdec/llvmir2hll/ir/pointer_type.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/struct_index_op_expr.h"
#include "retdec/llvmir2hll/ir/struct_type.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/types.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/// For more concise notation.
using WIGV = WrittenIntoGlobalsVisitor;

/**
* @brief Tests for the @c written_into_globals_visitor module.
*/
class WrittenIntoGlobalsVisitorTests: public TestsWithModule {};

TEST_F(WrittenIntoGlobalsVisitorTests,
NoGlobalsInModuleReturnsEmptySet) {
	// Set the module.
	//
	// def test():
	//    pass
	//

	VarSet ref;
	EXPECT_EQ(ref, WIGV::getWrittenIntoGlobals(testFunc, module));
}

TEST_F(WrittenIntoGlobalsVisitorTests,
TwoGlobalsNoReadNoWrittenInto) {
	// Set the module.
	//
	// a
	// b
	//
	// def test():
	//    pass
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	module->addGlobalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	module->addGlobalVar(varB);

	VarSet ref;
	EXPECT_EQ(ref, WIGV::getWrittenIntoGlobals(testFunc, module));
}

TEST_F(WrittenIntoGlobalsVisitorTests,
TwoGlobalsBothJustRead) {
	// Set the module.
	//
	// a
	// b
	//
	// def test():
	//    return a + b
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	module->addGlobalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	module->addGlobalVar(varB);
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(
		AddOpExpr::create(varA, varB)));
	testFunc->setBody(returnStmt);

	VarSet ref;
	EXPECT_EQ(ref, WIGV::getWrittenIntoGlobals(testFunc, module));
}

TEST_F(WrittenIntoGlobalsVisitorTests,
TwoGlobalsOneJustReadOneJustWrittenInto) {
	// Set the module.
	//
	// a
	// b
	//
	// def test():
	//    a = 1     (AssignStmt)
	//    return b
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	module->addGlobalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	module->addGlobalVar(varB);
	ShPtr<ReturnStmt> returnB(ReturnStmt::create(varB));
	ShPtr<AssignStmt> assignA1(AssignStmt::create(
		varA, ConstInt::create(1, 16), returnB));
	testFunc->setBody(assignA1);

	VarSet ref;
	ref.insert(varA);
	EXPECT_EQ(ref, WIGV::getWrittenIntoGlobals(testFunc, module));
}

TEST_F(WrittenIntoGlobalsVisitorTests,
TwoGlobalsBothJustWrittenInto) {
	// Set the module.
	//
	// a
	// b
	//
	// def test():
	//    a = 1     (AssignStmt)
	//    b = 1     (AssignStmt)
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	module->addGlobalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	module->addGlobalVar(varB);
	ShPtr<AssignStmt> assignB1(AssignStmt::create(
		varB, ConstInt::create(1, 16)));
	ShPtr<AssignStmt> assignA1(AssignStmt::create(
		varA, ConstInt::create(1, 16), assignB1));
	testFunc->setBody(assignA1);

	VarSet ref;
	ref.insert(varA);
	ref.insert(varB);
	EXPECT_EQ(ref, WIGV::getWrittenIntoGlobals(testFunc, module));
}

TEST_F(WrittenIntoGlobalsVisitorTests,
ThreeGlobalsTwoJustWrittenIntoOneUnused) {
	// Set the module.
	//
	// a
	// b
	// c
	//
	// def test():
	//    a = 1     (AssignStmt)
	//    b = 1     (AssignStmt)
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	module->addGlobalVar(varA);
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	module->addGlobalVar(varB);
	ShPtr<Variable> varC(Variable::create("c", IntType::create(16)));
	module->addGlobalVar(varC);
	ShPtr<AssignStmt> assignB1(AssignStmt::create(
		varB, ConstInt::create(1, 16)));
	ShPtr<AssignStmt> assignA1(AssignStmt::create(
		varA, ConstInt::create(1, 16), assignB1));
	testFunc->setBody(assignA1);

	VarSet ref;
	ref.insert(varA);
	ref.insert(varB);
	EXPECT_EQ(ref, WIGV::getWrittenIntoGlobals(testFunc, module));
}

TEST_F(WrittenIntoGlobalsVisitorTests,
OneGlobalUsedAsLoopInductionVariable) {
	// Set the module.
	//
	// a
	//
	// def test():
	//    for a in range(0, 10):
	//        pass
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	module->addGlobalVar(varA);
	ShPtr<ForLoopStmt> forLoopStmt(ForLoopStmt::create(
		varA, ConstInt::create(0, 16), LtOpExpr::create(varA, ConstInt::create(10, 16)),
		ConstInt::create(1, 16), EmptyStmt::create()));
	testFunc->setBody(forLoopStmt);

	VarSet ref;
	ref.insert(varA);
	EXPECT_EQ(ref, WIGV::getWrittenIntoGlobals(testFunc, module));
}

TEST_F(WrittenIntoGlobalsVisitorTests,
ArrayGlobalWhenSubscriptedDoesNotCountAsAWrittenIntoVariable) {
	// Set the module.
	//
	// a
	//
	// def test():
	//    a[0] = 1
	//
	ShPtr<Variable> varA(Variable::create("a", ArrayType::create(
		IntType::create(16), ArrayType::Dimensions())));
	module->addGlobalVar(varA);
	ShPtr<AssignStmt> assignA01(AssignStmt::create(
		ArrayIndexOpExpr::create(varA, ConstInt::create(0, 16)),
		ConstInt::create(1, 16)));
	testFunc->setBody(assignA01);

	VarSet ref;
	EXPECT_EQ(ref, WIGV::getWrittenIntoGlobals(testFunc, module));
}

TEST_F(WrittenIntoGlobalsVisitorTests,
StructGlobalWhenSubscriptedDoesNotCountAsAWrittenIntoVariable) {
	// Set the module.
	//
	// a
	//
	// def test():
	//    a[0] = 1
	//
	ShPtr<Variable> varA(Variable::create("a", StructType::create(
		StructType::ElementTypes())));
	module->addGlobalVar(varA);
	ShPtr<AssignStmt> assignA01(AssignStmt::create(
		StructIndexOpExpr::create(varA, ConstInt::create(0, 16)),
		ConstInt::create(1, 16)));
	testFunc->setBody(assignA01);

	VarSet ref;
	EXPECT_EQ(ref, WIGV::getWrittenIntoGlobals(testFunc, module));
}

TEST_F(WrittenIntoGlobalsVisitorTests,
DereferencingGlobalDoesNotCountAsAWrittenIntoVariable) {
	// Set the module.
	//
	// a
	//
	// def test():
	//    *a = 1
	//
	ShPtr<Variable> varA(Variable::create("a", PointerType::create(
		IntType::create(16))));
	module->addGlobalVar(varA);
	ShPtr<AssignStmt> assignA1(AssignStmt::create(
		DerefOpExpr::create(varA),
		ConstInt::create(1, 16)));
	testFunc->setBody(assignA1);

	VarSet ref;
	EXPECT_EQ(ref, WIGV::getWrittenIntoGlobals(testFunc, module));
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec

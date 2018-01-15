/**
* @file tests/llvmir2hll/optimizer/optimizers/deref_to_array_index_optimizer_tests.cpp
* @brief Tests for the @c deref_to_array_index_optimizer module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/array_index_op_expr.h"
#include "retdec/llvmir2hll/ir/const_float.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/deref_op_expr.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/float_type.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/struct_index_op_expr.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/optimizer/optimizers/deref_to_array_index_optimizer.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c deref_to_array_index_optimizer module.
*/
class DerefToArrayIndexOptimizerTests: public TestsWithModule {};

TEST_F(DerefToArrayIndexOptimizerTests,
OptimizerHasNonEmptyID) {
	ShPtr<DerefToArrayIndexOptimizer> optimizer(new DerefToArrayIndexOptimizer(
		module));

	EXPECT_TRUE(!optimizer->getId().empty()) <<
		"the optimizer should have a non-empty ID";
}

TEST_F(DerefToArrayIndexOptimizerTests,
VarPlusConstantOptimized) {
	// return *(a + 4);
	//
	// Optimized to return a[4].
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExpr(
		AddOpExpr::create(
			varA,
			ConstInt::create(4, 64)
	));
	ShPtr<DerefOpExpr> derefOpExpr(DerefOpExpr::create(addOpExpr));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(derefOpExpr));

	testFunc->setBody(returnStmt);

	Optimizer::optimize<DerefToArrayIndexOptimizer>(module);

	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ShPtr<ReturnStmt> outReturnBody(cast<ReturnStmt>(testFunc->getBody()));
	ASSERT_TRUE(outReturnBody) <<
		"expected `ReturnStmt`, "
		"got `" << testFunc->getBody() << "`";
	ShPtr<ArrayIndexOpExpr> outArray(cast<ArrayIndexOpExpr>(
		outReturnBody->getRetVal()));
	ASSERT_TRUE(outArray) <<
		"expected `ArrayIndexOpExpr`, "
		"got `" << outReturnBody->getRetVal() << "`";
}

TEST_F(DerefToArrayIndexOptimizerTests,
GlobalVarPlusConstantOptimized) {
	// int b = *(a + 4);
	// void test() {}
	//
	// is optimized to
	//
	// int b = a[4];
	// void test() {}
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<Variable> varB(Variable::create("b", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExpr(
		AddOpExpr::create(
			varA,
			ConstInt::create(4, 64)
	));
	ShPtr<DerefOpExpr> derefOpExpr(DerefOpExpr::create(addOpExpr));
	module->addGlobalVar(varB, derefOpExpr);

	Optimizer::optimize<DerefToArrayIndexOptimizer>(module);

	ShPtr<ArrayIndexOpExpr> outArray(cast<ArrayIndexOpExpr>(
		module->getInitForGlobalVar(varB)));
	ASSERT_TRUE(outArray) <<
		"expected `ArrayIndexOpExpr`, "
		"got `" << module->getInitForGlobalVar(varB) << "`";
}

TEST_F(DerefToArrayIndexOptimizerTests,
ConstantPlusVarOptimized) {
	// return *(4 + a);
	//
	// Optimized to return a[4].
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<ConstInt> constInt(ConstInt::create(4, 64));
	ShPtr<AddOpExpr> addOpExpr(
		AddOpExpr::create(
			constInt,
			varA
	));
	ShPtr<DerefOpExpr> derefOpExpr(DerefOpExpr::create(addOpExpr));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(derefOpExpr));

	testFunc->setBody(returnStmt);

	Optimizer::optimize<DerefToArrayIndexOptimizer>(module);

	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ShPtr<ReturnStmt> outReturnBody(cast<ReturnStmt>(testFunc->getBody()));
	ASSERT_TRUE(outReturnBody) <<
		"expected `ReturnStmt`, "
		"got `" << testFunc->getBody() << "`";
	ShPtr<ArrayIndexOpExpr> outArray(cast<ArrayIndexOpExpr>(
		outReturnBody->getRetVal()));
	ASSERT_TRUE(outArray) <<
		"expected `ArrayIndexOpExpr`, "
		"got `" << outReturnBody->getRetVal() << "`";
	ShPtr<Variable> outBase(cast<Variable>(outArray->getBase()));
	ASSERT_TRUE(outBase) <<
		"expected `Variable`, "
		"got `" << outArray->getBase() << "`";
	EXPECT_EQ(outBase, varA) <<
		"expected `" << varA << "`, "
		"got `" << outBase << "`";
	ShPtr<ConstInt> outIndex(cast<ConstInt>(outArray->getIndex()));
	ASSERT_TRUE(outIndex) <<
		"expected `ConstInt`, "
		"got `" << outArray->getIndex() << "`";
	EXPECT_EQ(outIndex->getValue(), constInt->getValue()) <<
		"expected `" << constInt << "`, "
		"got `" << outIndex << "`";
}

TEST_F(DerefToArrayIndexOptimizerTests,
ConstantPlusArrayIndexOpExprOptimized) {
	// return *(4 + a[2]);
	//
	// Optimized to return a[2][4].
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<ConstInt> constInt4(ConstInt::create(4, 64));
	ShPtr<ConstInt> constInt2(ConstInt::create(2, 64));
	ShPtr<ArrayIndexOpExpr> arrayIndexOpExpr(ArrayIndexOpExpr::create(
		varA,
		constInt2
	));
	ShPtr<AddOpExpr> addOpExpr(
		AddOpExpr::create(
			constInt4,
			arrayIndexOpExpr
	));
	ShPtr<DerefOpExpr> derefOpExpr(DerefOpExpr::create(addOpExpr));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(derefOpExpr));

	testFunc->setBody(returnStmt);

	Optimizer::optimize<DerefToArrayIndexOptimizer>(module);

	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ShPtr<ReturnStmt> outReturnBody(cast<ReturnStmt>(testFunc->getBody()));
	ASSERT_TRUE(outReturnBody) <<
		"expected `ReturnStmt`, "
		"got `" << testFunc->getBody() << "`";
	ShPtr<ArrayIndexOpExpr> outArray(cast<ArrayIndexOpExpr>(
		outReturnBody->getRetVal()));
	ASSERT_TRUE(outArray) <<
		"expected `ArrayIndexOpExpr`, "
		"got `" << outReturnBody->getRetVal() << "`";
	ShPtr<ArrayIndexOpExpr> outBaseArray(cast<ArrayIndexOpExpr>(
		outArray->getBase()));
	ASSERT_TRUE(outBaseArray) <<
		"expected `ArrayIndexOpExpr`, "
		"got `" << outArray->getBase() << "`";
	ShPtr<ConstInt> outIndex(cast<ConstInt>(outArray->getIndex()));
	ASSERT_TRUE(outIndex) <<
		"expected `ConstInt`, "
		"got `" << outArray->getIndex() << "`";
	EXPECT_EQ(outIndex->getValue(), constInt4->getValue()) <<
		"expected `" << constInt4 << "`, "
		"got `" << outIndex << "`";
	ShPtr<Variable> outBaseVar(cast<Variable>(outBaseArray->getBase()));
	ASSERT_TRUE(outBaseVar) <<
		"expected `Variable`, "
		"got `" << outBaseArray->getBase() << "`";
	EXPECT_EQ(outBaseVar, varA) <<
		"expected `" << varA << "`, "
		"got `" << outBaseVar << "`";
	ShPtr<ConstInt> outBaseIndex(cast<ConstInt>(outBaseArray->getIndex()));
	ASSERT_TRUE(outBaseIndex) <<
		"expected `ConstInt`, "
		"got `" << outBaseArray->getIndex() << "`";
	EXPECT_EQ(outBaseIndex->getValue(), constInt2->getValue()) <<
		"expected `" << constInt2 << "`, "
		"got `" << outBaseIndex << "`";
}

TEST_F(DerefToArrayIndexOptimizerTests,
ConstantPlusAccessToStructIndexOpOptimized) {
	// return *(4 + a.e0[0]);
	//
	// Optimized to return a.e0[0][4].
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<StructIndexOpExpr> structIndexOpExpr(
		StructIndexOpExpr::create(
			varA,
			ConstInt::create(0, 64)
	));
	ShPtr<ConstInt> constInt(ConstInt::create(4, 64));
	ShPtr<AddOpExpr> addOpExpr(
		AddOpExpr::create(
			constInt,
			structIndexOpExpr
	));
	ShPtr<DerefOpExpr> derefOpExpr(DerefOpExpr::create(addOpExpr));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(derefOpExpr));

	testFunc->setBody(returnStmt);

	Optimizer::optimize<DerefToArrayIndexOptimizer>(module);

	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ShPtr<ReturnStmt> outReturnBody(cast<ReturnStmt>(testFunc->getBody()));
	ASSERT_TRUE(outReturnBody) <<
		"expected `ReturnStmt`, "
		"got `" << testFunc->getBody() << "`";
	ShPtr<ArrayIndexOpExpr> outArray(cast<ArrayIndexOpExpr>(
		outReturnBody->getRetVal()));
	ASSERT_TRUE(outArray) <<
		"expected `ArrayIndexOpExpr`, "
		"got `" << outReturnBody->getRetVal() << "`";
	ShPtr<StructIndexOpExpr> outBase(cast<StructIndexOpExpr>(outArray->getBase()));
	ASSERT_TRUE(outBase) <<
		"expected `StructIndexOpExpr`, "
		"got `" << outArray->getBase() << "`";
	EXPECT_EQ(outBase, structIndexOpExpr) <<
		"expected `" << structIndexOpExpr << "`, "
		"got `" << outBase << "`";
	ShPtr<ConstInt> outIndex(cast<ConstInt>(outArray->getIndex()));
	ASSERT_TRUE(outIndex) <<
		"expected `ConstInt`, "
		"got `" << outArray->getIndex() << "`";
	EXPECT_EQ(outIndex->getValue(), constInt->getValue()) <<
		"expected `" << constInt << "`, "
		"got `" << outIndex << "`";
}

TEST_F(DerefToArrayIndexOptimizerTests,
VarPlusNotConstantNotOptimized) {
	// return *(a + a);
	//
	// Not optimized.
	//
	ShPtr<Variable> varA(Variable::create("a", IntType::create(16)));
	ShPtr<AddOpExpr> addOpExpr(
		AddOpExpr::create(
			varA,
			varA
	));
	ShPtr<DerefOpExpr> derefOpExpr(DerefOpExpr::create(addOpExpr));
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create(derefOpExpr));

	testFunc->setBody(returnStmt);

	Optimizer::optimize<DerefToArrayIndexOptimizer>(module);

	ASSERT_TRUE(testFunc->getBody()) <<
		"expected a non-empty body";
	ShPtr<ReturnStmt> outReturnBody(cast<ReturnStmt>(testFunc->getBody()));
	ASSERT_TRUE(outReturnBody) <<
		"expected `ReturnStmt`, "
		"got `" << testFunc->getBody() << "`";
	ShPtr<DerefOpExpr> outDerefOpExpr(cast<DerefOpExpr>(
		outReturnBody->getRetVal()));
	ASSERT_TRUE(outDerefOpExpr) <<
		"expected `DerefOpExpr`, "
		"got `" << outReturnBody->getRetVal() << "`";
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec

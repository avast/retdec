/**
* @file tests/llvmir2hll/optimizer/optimizers/c_array_arg_optimizer_tests.cpp
* @brief Tests for the @c c_array_arg_optimizer module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/address_op_expr.h"
#include "retdec/llvmir2hll/ir/array_index_op_expr.h"
#include "retdec/llvmir2hll/ir/array_type.h"
#include "retdec/llvmir2hll/ir/bit_cast_expr.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/call_stmt.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/pointer_type.h"
#include "llvmir2hll/ir/tests_with_module.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/optimizer/optimizers/c_array_arg_optimizer.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c c_array_arg_optimizer module.
*/
class CArrayArgOptimizerTests: public TestsWithModule {
protected:
	ShPtr<AddressOpExpr> createArrayArg(const std::string &varName);
	ShPtr<Variable> getVarFromArrayArg(ShPtr<AddressOpExpr> arrayArg);
	void checkThatArrayArgWasOptimized(ShPtr<Expression> arg,
		ShPtr<AddressOpExpr> arrayArg);
	void checkThatArrayArgWasNotOptimized(ShPtr<Expression> arg,
		ShPtr<Expression> arrayArg);
};

/**
* @brief Creates an array argument from the given variable name.
*/
ShPtr<AddressOpExpr> CArrayArgOptimizerTests::createArrayArg(
		const std::string &varName) {
	ArrayType::Dimensions dimensions;
	dimensions.push_back(10);
	ShPtr<Variable> var(Variable::create(varName,
		ArrayType::create(IntType::create(32), dimensions)));
	ShPtr<AddressOpExpr> arrayArg(AddressOpExpr::create(
		ArrayIndexOpExpr::create(var, ConstInt::create(0, 32))));
	return arrayArg;
}

/**
* @brief Returns the variable from the given array argument.
*/
ShPtr<Variable> CArrayArgOptimizerTests::getVarFromArrayArg(
		ShPtr<AddressOpExpr> arrayArg) {
	return cast<Variable>(cast<ArrayIndexOpExpr>(
		arrayArg->getOperand())->getBase());
}

/**
* @brief Checks that @a arg is an optimized array argument @a arrayArg.
*/
void CArrayArgOptimizerTests::checkThatArrayArgWasOptimized(
		ShPtr<Expression> arg, ShPtr<AddressOpExpr> arrayArg) {
	ShPtr<Variable> var(getVarFromArrayArg(arrayArg));
	ASSERT_EQ(var, arg) <<
		"expected `" << var << "`, " <<
		"got `" << arg << "`";
}

/**
* @brief Checks that @a arg is not an optimized array argument @a arrayArg.
*/
void CArrayArgOptimizerTests::checkThatArrayArgWasNotOptimized(
		ShPtr<Expression> arg, ShPtr<Expression> arrayArg) {
	ASSERT_EQ(arrayArg, arg) <<
		"expected `" << arrayArg << "`, " <<
		"got `" << arg << "`";
}

TEST_F(CArrayArgOptimizerTests,
OptimizerHasNonEmptyID) {
	ShPtr<CArrayArgOptimizer> optimizer(
		new CArrayArgOptimizer(module));

	EXPECT_TRUE(!optimizer->getId().empty()) <<
		"the optimizer should have a non-empty ID";
}

TEST_F(CArrayArgOptimizerTests,
InEmptyBodyThereIsNothingToOptimize) {
	// Optimize the module.
	Optimizer::optimize<CArrayArgOptimizer>(module);

	// Check that the output is correct.
	ASSERT_TRUE(isa<EmptyStmt>(testFunc->getBody())) <<
		"expected EmptyStmt, got " << testFunc->getBody();
	EXPECT_TRUE(!testFunc->getBody()->hasSuccessor()) <<
		"expected no successors of the statement, but got " <<
		testFunc->getBody()->getSuccessor();
}

TEST_F(CArrayArgOptimizerTests,
SingleArrayArgInFunctionCallIsOptimized) {
	//
	//    func(&x[0]);
	//
	// is optimized to
	//
	//    func(x);
	//
	ShPtr<AddressOpExpr> arrayArg(createArrayArg("x"));
	ExprVector args;
	args.push_back(arrayArg);
	ShPtr<CallExpr> callExpr(CallExpr::create(testFunc->getAsVar(), args));
	ShPtr<CallStmt> callStmt(CallStmt::create(callExpr));
	testFunc->setBody(callStmt);

	// Optimize the module.
	Optimizer::optimize<CArrayArgOptimizer>(module);

	// Check that the output is correct.
	checkThatArrayArgWasOptimized(callExpr->getArgs().front(), arrayArg);
}

TEST_F(CArrayArgOptimizerTests,
TwoArrayArgsInFunctionCallAreOptimized) {
	//
	//    func(&x[0], 1, &y[0]);
	//
	// is optimized to
	//
	//    func(x, 1, y);
	//
	ShPtr<AddressOpExpr> arrayArgX(createArrayArg("x"));
	ShPtr<AddressOpExpr> arrayArgY(createArrayArg("y"));
	ExprVector args;
	args.push_back(arrayArgX);
	args.push_back(ConstInt::create(1, 32));
	args.push_back(arrayArgY);
	ShPtr<CallExpr> callExpr(CallExpr::create(testFunc->getAsVar(), args));
	ShPtr<CallStmt> callStmt(CallStmt::create(callExpr));
	testFunc->setBody(callStmt);

	// Optimize the module.
	Optimizer::optimize<CArrayArgOptimizer>(module);

	// Check that the output is correct.
	checkThatArrayArgWasOptimized(callExpr->getArgs().front(), arrayArgX);
	checkThatArrayArgWasOptimized(callExpr->getArgs().back(), arrayArgY);
}

TEST_F(CArrayArgOptimizerTests,
ArrayArgIsOptimizedInTwoCalls) {
	//
	//    func(&x[0]);
	//    func(&y[0]);
	//
	// is optimized to
	//
	//    func(x);
	//    func(y);
	//
	ShPtr<AddressOpExpr> arrayArgY(createArrayArg("y"));
	ExprVector argsY;
	argsY.push_back(arrayArgY);
	ShPtr<CallExpr> callExprY(CallExpr::create(testFunc->getAsVar(), argsY));
	ShPtr<CallStmt> callStmtY(CallStmt::create(callExprY));
	ShPtr<AddressOpExpr> arrayArgX(createArrayArg("x"));
	ExprVector argsX;
	argsX.push_back(arrayArgX);
	ShPtr<CallExpr> callExprX(CallExpr::create(testFunc->getAsVar(), argsX));
	ShPtr<CallStmt> callStmtX(CallStmt::create(callExprX, callStmtY));
	testFunc->setBody(callStmtX);

	// Optimize the module.
	Optimizer::optimize<CArrayArgOptimizer>(module);

	// Check that the output is correct.
	checkThatArrayArgWasOptimized(callExprX->getArgs().front(), arrayArgX);
	checkThatArrayArgWasOptimized(callExprY->getArgs().front(), arrayArgY);
}

TEST_F(CArrayArgOptimizerTests,
ArrayArgOutsideOfFunctionCallIsNotOptimized) {
	//
	//    int a = &x[0];
	//
	// is not optimized.
	//
	ShPtr<AddressOpExpr> arrayArg(createArrayArg("x"));
	ShPtr<Variable> varA(Variable::create("a", IntType::create(32)));
	ShPtr<VarDefStmt> varDefStmt(VarDefStmt::create(varA, arrayArg));
	testFunc->setBody(varDefStmt);

	// Optimize the module.
	Optimizer::optimize<CArrayArgOptimizer>(module);

	// Check that the output is correct.
	ASSERT_EQ(arrayArg, varDefStmt->getInitializer());
}

TEST_F(CArrayArgOptimizerTests,
ArrayArgWithCastInFunctionCallIsNotOptimized) {
	//
	//    func((int *)&x[0])
	//
	// is not optimized.
	//
	ShPtr<AddressOpExpr> arrayArg(createArrayArg("x"));
	ShPtr<BitCastExpr> bitCast(BitCastExpr::create(arrayArg,
		PointerType::create(IntType::create(32))));
	ExprVector args;
	args.push_back(bitCast);
	ShPtr<CallExpr> callExpr(CallExpr::create(testFunc->getAsVar(), args));
	ShPtr<CallStmt> callStmt(CallStmt::create(callExpr));
	testFunc->setBody(callStmt);

	// Optimize the module.
	Optimizer::optimize<CArrayArgOptimizer>(module);

	// Check that the output is correct.
	checkThatArrayArgWasNotOptimized(callExpr->getArgs().front(), bitCast);
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec

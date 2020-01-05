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
	AddressOpExpr* createArrayArg(const std::string &varName);
	Variable* getVarFromArrayArg(AddressOpExpr* arrayArg);
	void checkThatArrayArgWasOptimized(Expression* arg,
		AddressOpExpr* arrayArg);
	void checkThatArrayArgWasNotOptimized(Expression* arg,
		Expression* arrayArg);
};

/**
* @brief Creates an array argument from the given variable name.
*/
AddressOpExpr* CArrayArgOptimizerTests::createArrayArg(
		const std::string &varName) {
	ArrayType::Dimensions dimensions;
	dimensions.push_back(10);
	Variable* var(Variable::create(varName,
		ArrayType::create(IntType::create(32), dimensions)));
	AddressOpExpr* arrayArg(AddressOpExpr::create(
		ArrayIndexOpExpr::create(var, ConstInt::create(0, 32))));
	return arrayArg;
}

/**
* @brief Returns the variable from the given array argument.
*/
Variable* CArrayArgOptimizerTests::getVarFromArrayArg(
		AddressOpExpr* arrayArg) {
	return cast<Variable>(cast<ArrayIndexOpExpr>(
		arrayArg->getOperand())->getBase());
}

/**
* @brief Checks that @a arg is an optimized array argument @a arrayArg.
*/
void CArrayArgOptimizerTests::checkThatArrayArgWasOptimized(
		Expression* arg, AddressOpExpr* arrayArg) {
	Variable* var(getVarFromArrayArg(arrayArg));
	ASSERT_EQ(var, arg) <<
		"expected `" << var << "`, " <<
		"got `" << arg << "`";
}

/**
* @brief Checks that @a arg is not an optimized array argument @a arrayArg.
*/
void CArrayArgOptimizerTests::checkThatArrayArgWasNotOptimized(
		Expression* arg, Expression* arrayArg) {
	ASSERT_EQ(arrayArg, arg) <<
		"expected `" << arrayArg << "`, " <<
		"got `" << arg << "`";
}

TEST_F(CArrayArgOptimizerTests,
OptimizerHasNonEmptyID) {
	CArrayArgOptimizer* optimizer(
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
	AddressOpExpr* arrayArg(createArrayArg("x"));
	ExprVector args;
	args.push_back(arrayArg);
	CallExpr* callExpr(CallExpr::create(testFunc->getAsVar(), args));
	CallStmt* callStmt(CallStmt::create(callExpr));
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
	AddressOpExpr* arrayArgX(createArrayArg("x"));
	AddressOpExpr* arrayArgY(createArrayArg("y"));
	ExprVector args;
	args.push_back(arrayArgX);
	args.push_back(ConstInt::create(1, 32));
	args.push_back(arrayArgY);
	CallExpr* callExpr(CallExpr::create(testFunc->getAsVar(), args));
	CallStmt* callStmt(CallStmt::create(callExpr));
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
	AddressOpExpr* arrayArgY(createArrayArg("y"));
	ExprVector argsY;
	argsY.push_back(arrayArgY);
	CallExpr* callExprY(CallExpr::create(testFunc->getAsVar(), argsY));
	CallStmt* callStmtY(CallStmt::create(callExprY));
	AddressOpExpr* arrayArgX(createArrayArg("x"));
	ExprVector argsX;
	argsX.push_back(arrayArgX);
	CallExpr* callExprX(CallExpr::create(testFunc->getAsVar(), argsX));
	CallStmt* callStmtX(CallStmt::create(callExprX, callStmtY));
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
	AddressOpExpr* arrayArg(createArrayArg("x"));
	Variable* varA(Variable::create("a", IntType::create(32)));
	VarDefStmt* varDefStmt(VarDefStmt::create(varA, arrayArg));
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
	AddressOpExpr* arrayArg(createArrayArg("x"));
	BitCastExpr* bitCast(BitCastExpr::create(arrayArg,
		PointerType::create(IntType::create(32))));
	ExprVector args;
	args.push_back(bitCast);
	CallExpr* callExpr(CallExpr::create(testFunc->getAsVar(), args));
	CallStmt* callStmt(CallStmt::create(callExpr));
	testFunc->setBody(callStmt);

	// Optimize the module.
	Optimizer::optimize<CArrayArgOptimizer>(module);

	// Check that the output is correct.
	checkThatArrayArgWasNotOptimized(callExpr->getArgs().front(), bitCast);
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec

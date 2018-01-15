/**
* @file tests/llvmir2hll/ir/array_index_op_expr_tests.cpp
* @brief Tests for the @c array_index_op_expr module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/ir/array_index_op_expr.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/variable.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c array_index_op_expr module.
*/
class ArrayIndexOpExprTests: public Test {};

//
// getBase()
//

TEST_F(ArrayIndexOpExprTests,
GetBaseReturnsBase) {
	ShPtr<Variable> base(Variable::create("base", IntType::create(32)));
	ShPtr<ConstInt> index(ConstInt::create(1, 32));
	ShPtr<ArrayIndexOpExpr> expr(ArrayIndexOpExpr::create(base, index));

	EXPECT_EQ(base, expr->getBase());
}

//
// getIndex()
//

TEST_F(ArrayIndexOpExprTests,
GetIndexReturnsIndex) {
	ShPtr<Variable> base(Variable::create("base", IntType::create(32)));
	ShPtr<ConstInt> index(ConstInt::create(1, 32));
	ShPtr<ArrayIndexOpExpr> expr(ArrayIndexOpExpr::create(base, index));

	EXPECT_EQ(index, expr->getIndex());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec

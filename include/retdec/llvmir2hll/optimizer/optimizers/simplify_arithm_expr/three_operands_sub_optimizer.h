/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/three_operands_sub_optimizer.h
* @brief A sub-optimization class that optimize expression like
*        (operand operator operand) operator operand or vica versa.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_SIMPLIFY_ARITHM_EXPR_THREE_OPERANDS_SUB_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_SIMPLIFY_ARITHM_EXPR_THREE_OPERANDS_SUB_OPTIMIZER_H

#include <string>

#include "retdec/llvmir2hll/ir/binary_op_expr.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/sub_optimizer.h"
#include "retdec/llvmir2hll/support/maybe.h"
#include "retdec/llvmir2hll/support/types.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief This optimizer changes expressions which have two operators and at least
*        two operands are constants.
*
* Optimizations are now only on these operators: +, -, <, <=, >, >=, ==, !=, ^.
*
* List of performed simplifications (by examples):
*
* @par Operator +
* ConstInt/ConstFloat + (ConstInt/ConstFloat +/- anytyhing).
* @code
* return 2 + (2 - a);
* @endcode
* can be optimized to
* @code
* return 4 + a;
* @endcode
* ConstInt/ConstFloat + (anytyhing +/- ConstInt/ConstFloat).
* @code
* return 2 + (a + 2);
* @endcode
* can be optimized to
* @code
* return 4 + a;
* @endcode
* (ConstInt/ConstFloat +/- anytyhing) + ConstInt/ConstFloat.
* @code
* return (2 - a) + 4;
* @endcode
* can be optimized to
* @code
* return 6 - a;
* @endcode
* (anytyhing +/- ConstInt/ConstFloat) + ConstInt/ConstFloat.
* @code
* return (a + 2) + 2;
* @endcode
* can be optimized to
* @code
* return a + 4;
* @endcode
*
* @par Operator -
* ConstInt/ConstFloat - (ConstInt/ConstFloat +/- anytyhing).
* @code
* return 2 - (1 - a);
* @endcode
* can be optimized to
* @code
* return 1 + a;
* @endcode
* ConstInt/ConstFloat - (anytyhing +/- ConstInt/ConstFloat).
* @code
* return 2 - (a + 1);
* @endcode
* can be optimized to
* @code
* return 1 - a;
* @endcode
* (ConstInt/ConstFloat +/- anytyhing) - ConstInt/ConstFloat.
* @code
* return (2 - a) - 1;
* @endcode
* can be optimized to
* @code
* return 1 - a;
* @endcode
* (anytyhing +/- ConstInt/ConstFloat) - ConstInt/ConstFloat.
* @code
* return (a + 2) - 1;
* @endcode
* can be optimized to
* @code
* return a + 1;
* @endcode
*
* @par Operator <, <=, >, >=, ==, !=
* (ConstInt/ConstFloat +/- anytyhing) <, <=, >, >=, ==, != ConstInt/ConstFloat.
* @code
* return (2 - a) <, <=, >, >=, ==, != 3;
* @endcode
* can be optimized to
* @code
* return a(negOpExpr) <, <=, >, >=, ==, != 1;
* @endcode
* (anytyhing +/- ConstInt/ConstFloat) <, <=, >, >=, ==, != ConstInt/ConstFloat.
* @code
* return (a + 2) <, <=, >, >=, ==, != 3;
* @endcode
* can be optimized to
* @code
* return a <, <=, >, >=, ==, != 1;
* @endcode
*
* @par Operator ^
* (anything relational operator anytyhing) ^ True - vice versa.
* @code
* return (2 < a) ^ True;
* @endcode
* can be optimized to
* @code
* return !(2 < a);
* @endcode
*
* @par Operator ||
* (var == ConstInt) || (var <= ConstInt).
* @code
* return (a == 2) || (a <= 4);
* @endcode
* can be optimized to
* @code
* return (a <= 4);
* @endcode
*
* Instances of this class have reference object semantics.
*
* This is a concrete sub optimizer which should not be subclassed.
*/
class ThreeOperandsSubOptimizer final: public SubOptimizer {
public:
	ThreeOperandsSubOptimizer(ShPtr<ArithmExprEvaluator> arithmExprEvaluator);
	virtual ~ThreeOperandsSubOptimizer() override;

	static ShPtr<SubOptimizer> create(ShPtr<ArithmExprEvaluator>
		arithmExprEvaluator);
	virtual std::string getId() const override;

private:
	/// Pair of expressions.
	using ExprPair = std::pair<ShPtr<Expression>, ShPtr<Expression>>;

private:
	/// @name Visitor Interface
	/// @{
	using SubOptimizer::visit;
	virtual void visit(ShPtr<AddOpExpr> expr) override;
	virtual void visit(ShPtr<SubOpExpr> expr) override;
	virtual void visit(ShPtr<LtOpExpr> expr) override;
	virtual void visit(ShPtr<LtEqOpExpr> expr) override;
	virtual void visit(ShPtr<GtOpExpr> expr) override;
	virtual void visit(ShPtr<GtEqOpExpr> expr) override;
	virtual void visit(ShPtr<EqOpExpr> expr) override;
	virtual void visit(ShPtr<NeqOpExpr> expr) override;
	virtual void visit(ShPtr<BitXorOpExpr> expr) override;
	virtual void visit(ShPtr<OrOpExpr> expr) override;
	/// @}

	bool analyzeOpOperOp(ShPtr<Expression> &constant, ShPtr<Expression> &expr,
		ShPtr<BinaryOpExpr> exprToAnalyze) const;
	ShPtr<Expression> getResult(ShPtr<Expression> expr) const;
	void tryOptimizeBitXorOpWithRelationalOperator(ShPtr<BitXorOpExpr> expr);
	Maybe<ExprPair> tryOptimizeExpressionWithRelationalOperator(
		ShPtr<BinaryOpExpr> expr);
	void tryOptimizeOrOpExprWithRelOperators(ShPtr<OrOpExpr>);
};

} // namespace llvmir2hll
} // namespace retdec

#endif

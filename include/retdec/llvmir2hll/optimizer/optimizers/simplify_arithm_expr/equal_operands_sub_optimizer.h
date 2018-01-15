/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/equal_operands_sub_optimizer.h
* @brief A sub-optimization class that optimize expression with equal operands.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_SIMPLIFY_ARITHM_EXPR_EQUAL_OPERANDS_SUB_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_SIMPLIFY_ARITHM_EXPR_EQUAL_OPERANDS_SUB_OPTIMIZER_H

#include <string>

#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/sub_optimizer.h"
#include "retdec/llvmir2hll/support/types.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief This optimizer changes expressions where the first and the second
*        operand is same one. Examples are mentioned below.
*
* Optimizations are now only on these operators: +, -, /, ==, !=.
*
* List of performed simplifications (by examples):
*
* @par Operator +
* First operand is equal to the second operand.
* @code
* return a + a;
* @endcode
* can be optimized to
* @code
* return 2 * a;
* @endcode
*
* @par Operator -
* First operand is equal to the second operand.
* @code
* return a - a;
* @endcode
* can be optimized to
* @code
* return 0;
* @endcode
*
* @par Operator /
* First operand is equal to the second operand.
* @code
* return a / a;
* @endcode
* can be optimized to
* @code
* return 1;
* @endcode
*
* @par Operator ==
* First operand is equal to the second operand. Operands are ConstInt or
* IntType Variable.
* @code
* return a == a;
* @endcode
* can be optimized to
* @code
* return 1(ConstBool);
* @endcode
*
* @par Operator !=
* First operand is equal to the second operand. Operands are ConstInt or
* IntType Variable.
* @code
* return a != a;
* @endcode
* can be optimized to
* @code
* return 0(ConstBool);
* @endcode
*
* Instances of this class have reference object semantics.
*
* This is a concrete sub-optimizer which should not be subclassed.
*/
class EqualOperandsSubOptimizer final: public SubOptimizer {
public:
	EqualOperandsSubOptimizer(ShPtr<ArithmExprEvaluator> arithmExprEvaluator);
	virtual ~EqualOperandsSubOptimizer() override;

	static ShPtr<SubOptimizer> create(ShPtr<ArithmExprEvaluator>
		arithmExprEvaluator);
	virtual std::string getId() const override;

private:
	/// @name Visitor Interface
	/// @{
	using SubOptimizer::visit;
	virtual void visit(ShPtr<AddOpExpr> expr) override;
	virtual void visit(ShPtr<SubOpExpr> expr) override;
	virtual void visit(ShPtr<DivOpExpr> expr) override;
	virtual void visit(ShPtr<EqOpExpr> expr) override;
	virtual void visit(ShPtr<NeqOpExpr> expr) override;
	/// @}

	bool isaConstIntOrIntTypeVariable(ShPtr<Expression> expr);
};

} // namespace llvmir2hll
} // namespace retdec

#endif

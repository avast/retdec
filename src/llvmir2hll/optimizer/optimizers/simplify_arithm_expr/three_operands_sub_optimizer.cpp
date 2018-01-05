/**
* @file src/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/three_operands_sub_optimizer.cpp
* @brief Implementation of ThreeOperandsSubOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/evaluator/arithm_expr_evaluator.h"
#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_xor_op_expr.h"
#include "retdec/llvmir2hll/ir/const_float.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/eq_op_expr.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/gt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/gt_op_expr.h"
#include "retdec/llvmir2hll/ir/lt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/lt_op_expr.h"
#include "retdec/llvmir2hll/ir/neg_op_expr.h"
#include "retdec/llvmir2hll/ir/neq_op_expr.h"
#include "retdec/llvmir2hll/ir/not_op_expr.h"
#include "retdec/llvmir2hll/ir/or_op_expr.h"
#include "retdec/llvmir2hll/ir/sub_op_expr.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/three_operands_sub_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

namespace {

/**
* @brief Return @c true if @a expr is a relational operator, @c false otherwise.
*
* @param[in] expr Expression to be checked.
*/
bool isRelationalOperator(ShPtr<Expression> expr) {
	return isa<LtOpExpr>(expr) || isa<LtEqOpExpr>(expr) ||
		isa<GtOpExpr>(expr) || isa<GtEqOpExpr>(expr) ||
		isa<EqOpExpr>(expr) || isa<NeqOpExpr>(expr);
}

}

REGISTER_AT_FACTORY("ThreeOperands", OP_OPER_OP_OPER_OP_SUB_OPTIMIZER_ID,
	SubOptimizerFactory, ThreeOperandsSubOptimizer::create);

/**
* @brief Constructs the ThreeOperandsSubOptimizer.
*
* @param[in] arithmExprEvaluator @a The used evaluator of arithmetical
*            expressions.
*/
ThreeOperandsSubOptimizer::ThreeOperandsSubOptimizer(ShPtr<ArithmExprEvaluator>
		arithmExprEvaluator): SubOptimizer(arithmExprEvaluator) {}

/**
* @brief Destructor.
*/
ThreeOperandsSubOptimizer::~ThreeOperandsSubOptimizer() {}

/**
* @brief Creates a new ThreeOperandsSubOptimizer.
*
* @param[in] arithmExprEvaluator @a The used evaluator of arithmetical
*            expressions.
*/
ShPtr<SubOptimizer> ThreeOperandsSubOptimizer::create(ShPtr<ArithmExprEvaluator>
		arithmExprEvaluator) {
	return ShPtr<SubOptimizer>(new ThreeOperandsSubOptimizer(
		arithmExprEvaluator));
}

std::string ThreeOperandsSubOptimizer::getId() const {
	return OP_OPER_OP_OPER_OP_SUB_OPTIMIZER_ID;
}

void ThreeOperandsSubOptimizer::visit(ShPtr<AddOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	// Optimizations dependent on the first Constant operand or on the second
	// Constant operand.
	ShPtr<Expression> firstConstant;
	ShPtr<Expression> opOperopExpr;
	if (analyzeOpOperOp(firstConstant, opOperopExpr, expr)) {
		// Something like ConstInt/ConstFloat +
		// (ConstInt/ConstFloat + or - anything)*vice versa*. or
		// (ConstInt/ConstFloat + or - anything)*vice versa* + ConstInt/ConstFloat.
		ShPtr<AddOpExpr> addOpExpr(cast<AddOpExpr>(opOperopExpr));
		if (addOpExpr) {
			// Something like ConstInt/ConstFloat +
			// (ConstInt/ConstFloat + anything)*vice versa*. or
			// (ConstInt/ConstFloat + anything)*vice versa* + ConstInt/ConstFloat.
			ShPtr<Expression> secondConstant;
			ShPtr<Expression> exprInAddOpExpr;
			if (!analyzeOpOperOp(secondConstant, exprInAddOpExpr, addOpExpr)) {
				// Something like ConstInt/ConstFloat +
				// (anything + anything) anything in both operands are not
				// ConstInt/ConstFloat.
				return;
			};
			// Get summation of two constants.
			ShPtr<Expression> result(getResult(AddOpExpr::create(firstConstant,
				secondConstant)));
			if (result) {
				// Result is Constant + anything.
				ShPtr<AddOpExpr> add(AddOpExpr::create(result, exprInAddOpExpr));
				optimizeExpr(expr, add);
				return;
			}
			// Nothing was optimized.
			return;
		}
	}

	// Optimizations dependent on the first Constant operand.
	if (isConstFloatOrConstInt(expr->getFirstOperand())) {
		// Optimization like ConstInt/ConstFloat +
		// (ConstInt/ConstFloat/anything + - ConstInt/ConstFloat/anything).
		ShPtr<SubOpExpr> subOpExpr(cast<SubOpExpr>(expr->getSecondOperand()));
		if (subOpExpr) {
			// Optimization like ConstInt/ConstFloat +
			// (ConstInt/ConstFloat/anything - ConstInt/ConstFloat/anything).
			ShPtr<Expression> constSecOp;
			ShPtr<Expression> exprSecOp;
			if (!analyzeOpOperOp(constSecOp, exprSecOp, subOpExpr)) {
				// Something like ConstInt/ConstFloat +
				// (anything - anything) anything in both operands are not
				// ConstInt/ConstFloat.
				return;
			};
			if (constSecOp->isEqualTo(subOpExpr->getFirstOperand())) {
				// Optimization like ConstInt/ConstFloat +
				// (ConstInt/ConstFloat/anything - anything).
				ShPtr<Expression> result(getResult(AddOpExpr::create(
					expr->getFirstOperand(), constSecOp)));
				if (result) {
					ShPtr<SubOpExpr> sub(SubOpExpr::create(result, exprSecOp));
					optimizeExpr(expr, sub);
					return;
				}
			} else if (constSecOp->isEqualTo(subOpExpr->getSecondOperand())) {
				// Optimization like ConstInt/ConstFloat +
				// (anything - ConstInt/ConstFloat/anything).
				ShPtr<Expression> result(getResult(SubOpExpr::create(
					expr->getFirstOperand(), constSecOp)));
				if (result) {
					// Result is Constant + anything.
					ShPtr<AddOpExpr> add(AddOpExpr::create(result, exprSecOp));
					optimizeExpr(expr, add);
					return;
				}
			}
		}
	}

	// Optimizations dependent on the second Constant operand.
	if (isConstFloatOrConstInt(expr->getSecondOperand())) {
		// Optimization like
		// (ConstInt/ConstFloat/anything + - ConstInt/ConstFloat/anything)
		// + ConstInt/ConstFloat.
		ShPtr<SubOpExpr> subOpExpr(cast<SubOpExpr>(expr->getFirstOperand()));
		if (subOpExpr) {
			// Optimization like
			// (ConstInt/ConstFloat/anything - ConstInt/ConstFloat/anything)
			// + ConstInt/ConstFloat.
			ShPtr<Expression> constSecOp;
			ShPtr<Expression> exprSecOp;
			if (!analyzeOpOperOp(constSecOp, exprSecOp, subOpExpr)) {
				// Something like (anything - anything) + ConstInt/ConstFloat.
				// "anything" in both operands are not ConstInt/ConstFloat.
				return;
			};
			if (constSecOp->isEqualTo(subOpExpr->getFirstOperand())) {
				// Optimization like
				// (ConstInt/ConstFloat - anything) + ConstInt/ConstFloat.
				ShPtr<Expression> result(getResult(AddOpExpr::create(
					expr->getSecondOperand(), constSecOp)));
				if (result) {
					// Result is Constant - anything.
					ShPtr<SubOpExpr> sub(SubOpExpr::create(result, exprSecOp));
					optimizeExpr(expr, sub);
					return;
				}
			} else if (constSecOp->isEqualTo(subOpExpr->getSecondOperand())) {
				// Optimization like
				// (anything - ConstInt/ConstFloat) + ConstInt/ConstFloat.
				ShPtr<Expression> result(getResult(SubOpExpr::create(constSecOp,
					expr->getSecondOperand())));
				if (result) {
					// Result is Anything - constant.
					ShPtr<SubOpExpr> sub(SubOpExpr::create(exprSecOp, result));
					optimizeExpr(expr, sub);
					return;
				}
			}
		}
	}
}

void ThreeOperandsSubOptimizer::visit(ShPtr<SubOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	// Optimizations dependent on the first Constant operand.
	if (isConstFloatOrConstInt(expr->getFirstOperand())) {
		// Optimization like ConstInt/ConstFloat -
		// (ConstInt/ConstFloat/anything + - ConstInt/ConstFloat/anything).
		ShPtr<AddOpExpr> addOpExpr(cast<AddOpExpr>(expr->getSecondOperand()));
		ShPtr<SubOpExpr> subOpExpr(cast<SubOpExpr>(expr->getSecondOperand()));
		ShPtr<BinaryOpExpr> binOpExpr(cast<BinaryOpExpr>(expr->getSecondOperand()));

		// Find constant and not constant in AddOpExpr or SubOpExpr.
		ShPtr<Expression> constSecOp;
		ShPtr<Expression> exprSecOp;
		if (addOpExpr || subOpExpr) {
			if (!analyzeOpOperOp(constSecOp, exprSecOp, binOpExpr)) {
				// Something like ConstInt/ConstFloat -
				// (anything + - anything) anything in both operands are not
				// ConstInt/ConstFloat.
				return;
			};
		}
		if (addOpExpr) {
			// Optimization like ConstInt/ConstFloat -
			// (ConstInt/ConstFloat/anything + ConstInt/ConstFloat/anything).
			ShPtr<Expression> result(getResult(SubOpExpr::create(
				expr->getFirstOperand(), constSecOp)));
			if (result) {
				// Result is Constant + anything.
				ShPtr<SubOpExpr> sub(SubOpExpr::create(result, exprSecOp));
				optimizeExpr(expr, sub);
				return;
			}
			// Nothing was optimized.
			return;
		} else if (subOpExpr) {
			// Optimization like ConstInt/ConstFloat -
			// (ConstInt/ConstFloat/anything - ConstInt/ConstFloat/anything).
			if (constSecOp->isEqualTo(subOpExpr->getFirstOperand())) {
				// Optimization like ConstInt/ConstFloat -
				// (ConstInt/ConstFloat - anything).
				ShPtr<Expression> result(getResult(SubOpExpr::create(
					expr->getFirstOperand(), constSecOp)));
				if (result) {
					// Result is Constant + anything.
					ShPtr<AddOpExpr> add(AddOpExpr::create(result, exprSecOp));
					optimizeExpr(expr, add);
					return;
				}
			} else if (constSecOp->isEqualTo(subOpExpr->getSecondOperand())) {
				// Optimization like ConstInt/ConstFloat -
				// (anything - ConstInt/ConstFloat/anything).
				ShPtr<Expression> result(getResult(AddOpExpr::create(
					expr->getFirstOperand(), constSecOp)));
				if (result) {
					// Result is Constant - anything.
					ShPtr<SubOpExpr> sub(SubOpExpr::create(result, exprSecOp));
					optimizeExpr(expr, sub);
					return;
				}
			}
		}
	}

	// Optimizations dependent on the second Constant operand.
	if (isConstFloatOrConstInt(expr->getSecondOperand())) {
		// Optimization like
		// (ConstInt/ConstFloat/anything + - ConstInt/ConstFloat/anything)
		// - ConstInt/ConstFloat.
		ShPtr<AddOpExpr> addOpExpr(cast<AddOpExpr>(expr->getFirstOperand()));
		ShPtr<SubOpExpr> subOpExpr(cast<SubOpExpr>(expr->getFirstOperand()));
		ShPtr<BinaryOpExpr> binOpExpr(cast<BinaryOpExpr>(expr->getFirstOperand()));

		// Find constant and not constant in AddOpExpr or SubOpExpr.
		ShPtr<Expression> constSecOp;
		ShPtr<Expression> exprSecOp;
		if (addOpExpr || subOpExpr) {
			if (!analyzeOpOperOp(constSecOp, exprSecOp, binOpExpr)) {
				// Something like (anything + - anything) - ConstInt/ConstFloat.
				// "anything" in both operands are not ConstInt/ConstFloat.
				return;
			};
		}
		if (addOpExpr) {
			// Optimization like
			// (ConstInt/ConstFloat/anything + ConstInt/ConstFloat/anything)
			// - ConstInt/ConstFloat.
			if (constSecOp->isEqualTo(addOpExpr->getFirstOperand())) {
				// Optimization like
				// (ConstInt/ConstFloat + ConstInt/ConstFloat/anything)
				// - ConstInt/ConstFloat.
				ShPtr<Expression> result(getResult(SubOpExpr::create(constSecOp,
					expr->getFirstOperand())));
				if (result) {
					// Result is Constant + anything.
					ShPtr<AddOpExpr> add(AddOpExpr::create(result, exprSecOp));
					optimizeExpr(expr, add);
					return;
				}
			} else if (constSecOp->isEqualTo(addOpExpr->getSecondOperand())) {
				// Optimization like
				// (anything + ConstInt/ConstFloat/anything)
				// - ConstInt/ConstFloat.
				ShPtr<Expression> result(getResult(SubOpExpr::create(
					expr->getSecondOperand(), constSecOp)));
				if (result) {
					// Result is Anything - constant.
					ShPtr<SubOpExpr> sub(SubOpExpr::create(exprSecOp, result));
					optimizeExpr(expr, sub);
					return;
				}
			}
		} else if (subOpExpr) {
			// Optimization like
			// (ConstInt/ConstFloat/anything - ConstInt/ConstFloat/anything)
			// - ConstInt/ConstFloat.
			if (constSecOp->isEqualTo(subOpExpr->getFirstOperand())) {
				// Optimization like
				// (ConstInt/ConstFloat - anything)
				// - ConstInt/ConstFloat.
				ShPtr<Expression> result(getResult(SubOpExpr::create(constSecOp,
					expr->getSecondOperand())));
				if (result) {
					// Result is Constant - anything.
					ShPtr<SubOpExpr> sub(SubOpExpr::create(result, exprSecOp));
					optimizeExpr(expr, sub);
					return;
				}
			} else if (constSecOp->isEqualTo(subOpExpr->getSecondOperand())) {
				// Optimization like
				// (anything - ConstInt/ConstFloat)
				// - ConstInt/ConstFloat.
				ShPtr<Expression> result(getResult(AddOpExpr::create(constSecOp,
					expr->getSecondOperand())));
				if (result) {
					// Result is anything - Constant.
					ShPtr<SubOpExpr> sub(SubOpExpr::create(exprSecOp, result));
					optimizeExpr(expr, sub);
					return;
				}
			}
		}
	}
}

/**
* @brief Find the @c Constant in @a exprToAnalyze.
*
* @param[in, out] constant Finded constant save to this parameter.
* @param[in, out] expr Second expresion from @a exprToAnalyze save to this
*                 parameter.
* @param[in] exprToAnalyze Expression to analyze.
*
* @return If @a exprToAnalyze is the null pointer or @c Constant was not fined
*         return @c false, otherwise return @c true.
*/
bool ThreeOperandsSubOptimizer::analyzeOpOperOp(ShPtr<Expression> &constant,
		ShPtr<Expression> &expr, ShPtr<BinaryOpExpr> exprToAnalyze) const {

	// Is exprToAnalyze a BinaryOpExpr?
	if (!exprToAnalyze) {
		return false;
	}

	if (isConstFloatOrConstInt(exprToAnalyze->getFirstOperand())) {
		// (ConstInt/ConstFloat + anything).
		constant = exprToAnalyze->getFirstOperand();
		expr = exprToAnalyze->getSecondOperand();
	} else if (isConstFloatOrConstInt(exprToAnalyze->getSecondOperand())) {
		// (anything + ConstInt/ConstFloat).
		constant = exprToAnalyze->getSecondOperand();
		expr = exprToAnalyze->getFirstOperand();
	} else {
		// No constant was found..
		return false;
	}

	// Constant was found.
	return true;
}

void ThreeOperandsSubOptimizer::visit(ShPtr<LtOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	Maybe<ExprPair> exprPair(tryOptimizeExpressionWithRelationalOperator(expr));
	if (exprPair) {
		optimizeExpr(expr, LtOpExpr::create(exprPair->first, exprPair->second));
	}
}

void ThreeOperandsSubOptimizer::visit(ShPtr<LtEqOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	Maybe<ExprPair> exprPair(tryOptimizeExpressionWithRelationalOperator(expr));
	if (exprPair) {
		optimizeExpr(expr, LtEqOpExpr::create(exprPair->first, exprPair->second));
	}
}

void ThreeOperandsSubOptimizer::visit(ShPtr<GtOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	Maybe<ExprPair> exprPair(tryOptimizeExpressionWithRelationalOperator(expr));
	if (exprPair) {
		optimizeExpr(expr, GtOpExpr::create(exprPair->first, exprPair->second));
	}
}

void ThreeOperandsSubOptimizer::visit(ShPtr<GtEqOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	Maybe<ExprPair> exprPair(tryOptimizeExpressionWithRelationalOperator(expr));
	if (exprPair) {
		optimizeExpr(expr, GtEqOpExpr::create(exprPair->first, exprPair->second));
	}
}

void ThreeOperandsSubOptimizer::visit(ShPtr<EqOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	Maybe<ExprPair> exprPair(tryOptimizeExpressionWithRelationalOperator(expr));
	if (exprPair) {
		optimizeExpr(expr, EqOpExpr::create(exprPair->first, exprPair->second));
	}
}

void ThreeOperandsSubOptimizer::visit(ShPtr<NeqOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	Maybe<ExprPair> exprPair(tryOptimizeExpressionWithRelationalOperator(expr));
	if (exprPair) {
		optimizeExpr(expr, NeqOpExpr::create(exprPair->first, exprPair->second));
	}
}

void ThreeOperandsSubOptimizer::visit(ShPtr<BitXorOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	tryOptimizeBitXorOpWithRelationalOperator(expr);
}

void ThreeOperandsSubOptimizer::visit(ShPtr<OrOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	tryOptimizeOrOpExprWithRelOperators(expr);
}

/**
* @brief Optimizes expression like @code (var == ConstInt) || (var <= ConstInt)
*        @endcode to @code var <= ConstInt @endcode.
*
* @param[in] expr Expression to optimize.
*/
void ThreeOperandsSubOptimizer::tryOptimizeOrOpExprWithRelOperators(ShPtr<
		OrOpExpr> expr) {
	ShPtr<EqOpExpr> firstOpEqOp(cast<EqOpExpr>(expr->getFirstOperand()));
	ShPtr<LtEqOpExpr> secOpLtEqOp(cast<LtEqOpExpr>(expr->getSecondOperand()));
	if (!firstOpEqOp || !secOpLtEqOp) {
		// Not (var == ConstInt) || (var <= ConstInt).
		return;
	}

	if (!isa<Variable>(firstOpEqOp->getFirstOperand()) || !isa<Variable>(
			secOpLtEqOp->getFirstOperand())) {
		// Variables are not on first place on operands.
		return;
	}

	if (!firstOpEqOp->getFirstOperand()->isEqualTo(secOpLtEqOp->getFirstOperand())) {
		// Variables are not equal.
		return;
	}

	ShPtr<ConstInt> firstOpConstInt(
		cast<ConstInt>(firstOpEqOp->getSecondOperand()));
	ShPtr<ConstInt> secOpConstInt(
		cast<ConstInt>(secOpLtEqOp->getSecondOperand()));

	if (!firstOpConstInt || !secOpConstInt) {
		// Operands doesn't have integer constants.
		return;
	}

	// Evaluate two ConstInt's and thank to result optimize or not.
	ShPtr<LtEqOpExpr> ltEqOpExpr(
		LtEqOpExpr::create(firstOpConstInt, secOpConstInt));
	ShPtr<ConstBool> constBool(
		cast<ConstBool>(arithmExprEvaluator->evaluate(ltEqOpExpr)));
	if (constBool && constBool->getValue()) {
		// If firstConstInt is lower than secConstInt, can be optimized.
		optimizeExpr(expr, secOpLtEqOp);
	}
}

/**
* @brief Try optimize BitXorOpExpr when one operand is relational operator and
*        the second one is a ConstBool operand.
*
* @param[in] expr BitXorOpExpr to optimize.
*/
void ThreeOperandsSubOptimizer::tryOptimizeBitXorOpWithRelationalOperator(ShPtr<
		BitXorOpExpr> expr) {
	ShPtr<Expression> firstOp(expr->getFirstOperand());
	ShPtr<Expression> secOp(expr->getSecondOperand());

	// Expression like (a < 2) ^ True can be optimized to !(a < 2).
	ShPtr<NotOpExpr> notOpExpr;
	if (isRelationalOperator(firstOp)) {
		ShPtr<ConstBool> constBoolSecOp(cast<ConstBool>(secOp));
		if (constBoolSecOp && constBoolSecOp->getValue()) {
			// ConstBool must be True.
			notOpExpr = NotOpExpr::create(firstOp);
		}
	} else if (isRelationalOperator(secOp) && isa<ConstBool>(firstOp)) {
		ShPtr<ConstBool> constBoolFirstOp(cast<ConstBool>(firstOp));
		if (constBoolFirstOp && constBoolFirstOp->getValue()) {
			// ConstBool must be True.
			notOpExpr = NotOpExpr::create(secOp);
		}
	}

	if (notOpExpr) {
		optimizeExpr(expr, notOpExpr);
	}
}

/**
* @brief Try to optimize relational @a expr.
*
* @param[in] expr An expression to optimize.
*
* @return If @a expr can be optimized return the new first and the new second
*         operand, otherwise the null pointer.
*
* @par Preconditions
*  - @a expr is BinaryOpExpr with relational operator.
*/
Maybe<ThreeOperandsSubOptimizer::ExprPair> ThreeOperandsSubOptimizer::
		tryOptimizeExpressionWithRelationalOperator(ShPtr<BinaryOpExpr> expr) {
	if (isConstFloatOrConstInt(expr->getSecondOperand())) {
		// Optimization like
		// (ConstInt/ConstFloat/anything + - ConstInt/ConstFloat/anything)
		// < ConstInt/ConstFloat.
		ShPtr<AddOpExpr> addOpExpr(cast<AddOpExpr>(expr->getFirstOperand()));
		ShPtr<SubOpExpr> subOpExpr(cast<SubOpExpr>(expr->getFirstOperand()));
		ShPtr<BinaryOpExpr> binOpExpr(cast<BinaryOpExpr>(expr->getFirstOperand()));

		// Find constant and not constant in AddOpExpr or SubOpExpr.
		ShPtr<Expression> constSecOp;
		ShPtr<Expression> exprSecOp;
		if (addOpExpr || subOpExpr) {
			if (!analyzeOpOperOp(constSecOp, exprSecOp, binOpExpr)) {
				// Something like (anything + - anything) < ConstInt/ConstFloat.
				// "anything" in both operands are not ConstInt/ConstFloat.
				return Nothing<ExprPair>();
			};
		}
		if (addOpExpr) {
			// Optimization like
			// (ConstInt/ConstFloat + ConstInt/ConstFloat/anything)
			// < ConstInt/ConstFloat.
			ShPtr<Expression> result(getResult(SubOpExpr::create(
				expr->getSecondOperand(), constSecOp)));
			if (result) {
				// Result is anything relational operator Constant.
				return Just(ExprPair(exprSecOp, result));
			}
		} else if (subOpExpr) {
			// Optimization like
			// (ConstInt/ConstFloat/anything - ConstInt/ConstFloat/anything)
			// < ConstInt/ConstFloat.
			// Need to first check the second operand because when we have
			// expression like this 3 - 2 < 4 we don't want to create
			// 2(negOpExpr) < 1 but we want 3 < 6. Creating of NegOpExpr is in
			// else if clasue.
			if (constSecOp->isEqualTo(subOpExpr->getSecondOperand())) {
				// Optimization like
				// (anything - ConstInt/ConstFloat)
				// < ConstInt/ConstFloat.
				ShPtr<Expression> result(getResult(AddOpExpr::create(
					expr->getSecondOperand(), constSecOp)));
				if (result) {
					// Result is anything relational operator Constant.
					return Just(ExprPair(exprSecOp, result));
				}
			} else if (constSecOp->isEqualTo(subOpExpr->getFirstOperand())) {
				// Optimization like
				// (ConstInt/ConstFloat - anything)
				// < ConstInt/ConstFloat.
				ShPtr<Expression> result(getResult(SubOpExpr::create(
					expr->getSecondOperand(), constSecOp)));
				ShPtr<NegOpExpr> negOpExpr(NegOpExpr::create(exprSecOp));
				if (result) {
					// Result is anything(negOpExpr) relational operator Constant.
					return Just(ExprPair(negOpExpr, result));
				}
			}
		}
	}
	return Nothing<ExprPair>();
}

/**
* @brief Evaluate @a expr and return result.
*
* @param[in] expr Expression to evaluate.
*
* @return The result. If counting was not successful return the null pointer.
*/
ShPtr<Expression> ThreeOperandsSubOptimizer::getResult(ShPtr<Expression> expr) const {
	return arithmExprEvaluator->evaluate(expr);
}

} // namespace llvmir2hll
} // namespace retdec

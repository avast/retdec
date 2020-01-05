/**
* @file src/llvmir2hll/optimizer/optimizers/simplify_arithm_expr/three_operands_sub_optimizer.cpp
* @brief Implementation of ThreeOperandsSubOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <optional>

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
bool isRelationalOperator(Expression* expr) {
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
ThreeOperandsSubOptimizer::ThreeOperandsSubOptimizer(ArithmExprEvaluator*
		arithmExprEvaluator): SubOptimizer(arithmExprEvaluator) {}

/**
* @brief Creates a new ThreeOperandsSubOptimizer.
*
* @param[in] arithmExprEvaluator @a The used evaluator of arithmetical
*            expressions.
*/
SubOptimizer* ThreeOperandsSubOptimizer::create(ArithmExprEvaluator*
		arithmExprEvaluator) {
	return new ThreeOperandsSubOptimizer(arithmExprEvaluator);
}

std::string ThreeOperandsSubOptimizer::getId() const {
	return OP_OPER_OP_OPER_OP_SUB_OPTIMIZER_ID;
}

void ThreeOperandsSubOptimizer::visit(AddOpExpr* expr) {
	OrderedAllVisitor::visit(expr);

	// Optimizations dependent on the first Constant operand or on the second
	// Constant operand.
	Expression* firstConstant;
	Expression* opOperopExpr;
	if (analyzeOpOperOp(firstConstant, opOperopExpr, expr)) {
		// Something like ConstInt/ConstFloat +
		// (ConstInt/ConstFloat + or - anything)*vice versa*. or
		// (ConstInt/ConstFloat + or - anything)*vice versa* + ConstInt/ConstFloat.
		AddOpExpr* addOpExpr(cast<AddOpExpr>(opOperopExpr));
		if (addOpExpr) {
			// Something like ConstInt/ConstFloat +
			// (ConstInt/ConstFloat + anything)*vice versa*. or
			// (ConstInt/ConstFloat + anything)*vice versa* + ConstInt/ConstFloat.
			Expression* secondConstant;
			Expression* exprInAddOpExpr;
			if (!analyzeOpOperOp(secondConstant, exprInAddOpExpr, addOpExpr)) {
				// Something like ConstInt/ConstFloat +
				// (anything + anything) anything in both operands are not
				// ConstInt/ConstFloat.
				return;
			};
			// Get summation of two constants.
			Expression* result(getResult(AddOpExpr::create(firstConstant,
				secondConstant)));
			if (result) {
				// Result is Constant + anything.
				AddOpExpr* add(AddOpExpr::create(result, exprInAddOpExpr));
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
		SubOpExpr* subOpExpr(cast<SubOpExpr>(expr->getSecondOperand()));
		if (subOpExpr) {
			// Optimization like ConstInt/ConstFloat +
			// (ConstInt/ConstFloat/anything - ConstInt/ConstFloat/anything).
			Expression* constSecOp;
			Expression* exprSecOp;
			if (!analyzeOpOperOp(constSecOp, exprSecOp, subOpExpr)) {
				// Something like ConstInt/ConstFloat +
				// (anything - anything) anything in both operands are not
				// ConstInt/ConstFloat.
				return;
			};
			if (constSecOp->isEqualTo(subOpExpr->getFirstOperand())) {
				// Optimization like ConstInt/ConstFloat +
				// (ConstInt/ConstFloat/anything - anything).
				Expression* result(getResult(AddOpExpr::create(
					expr->getFirstOperand(), constSecOp)));
				if (result) {
					SubOpExpr* sub(SubOpExpr::create(result, exprSecOp));
					optimizeExpr(expr, sub);
					return;
				}
			} else if (constSecOp->isEqualTo(subOpExpr->getSecondOperand())) {
				// Optimization like ConstInt/ConstFloat +
				// (anything - ConstInt/ConstFloat/anything).
				Expression* result(getResult(SubOpExpr::create(
					expr->getFirstOperand(), constSecOp)));
				if (result) {
					// Result is Constant + anything.
					AddOpExpr* add(AddOpExpr::create(result, exprSecOp));
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
		SubOpExpr* subOpExpr(cast<SubOpExpr>(expr->getFirstOperand()));
		if (subOpExpr) {
			// Optimization like
			// (ConstInt/ConstFloat/anything - ConstInt/ConstFloat/anything)
			// + ConstInt/ConstFloat.
			Expression* constSecOp;
			Expression* exprSecOp;
			if (!analyzeOpOperOp(constSecOp, exprSecOp, subOpExpr)) {
				// Something like (anything - anything) + ConstInt/ConstFloat.
				// "anything" in both operands are not ConstInt/ConstFloat.
				return;
			};
			if (constSecOp->isEqualTo(subOpExpr->getFirstOperand())) {
				// Optimization like
				// (ConstInt/ConstFloat - anything) + ConstInt/ConstFloat.
				Expression* result(getResult(AddOpExpr::create(
					expr->getSecondOperand(), constSecOp)));
				if (result) {
					// Result is Constant - anything.
					SubOpExpr* sub(SubOpExpr::create(result, exprSecOp));
					optimizeExpr(expr, sub);
					return;
				}
			} else if (constSecOp->isEqualTo(subOpExpr->getSecondOperand())) {
				// Optimization like
				// (anything - ConstInt/ConstFloat) + ConstInt/ConstFloat.
				Expression* result(getResult(SubOpExpr::create(constSecOp,
					expr->getSecondOperand())));
				if (result) {
					// Result is Anything - constant.
					SubOpExpr* sub(SubOpExpr::create(exprSecOp, result));
					optimizeExpr(expr, sub);
					return;
				}
			}
		}
	}
}

void ThreeOperandsSubOptimizer::visit(SubOpExpr* expr) {
	OrderedAllVisitor::visit(expr);

	// Optimizations dependent on the first Constant operand.
	if (isConstFloatOrConstInt(expr->getFirstOperand())) {
		// Optimization like ConstInt/ConstFloat -
		// (ConstInt/ConstFloat/anything + - ConstInt/ConstFloat/anything).
		AddOpExpr* addOpExpr(cast<AddOpExpr>(expr->getSecondOperand()));
		SubOpExpr* subOpExpr(cast<SubOpExpr>(expr->getSecondOperand()));
		BinaryOpExpr* binOpExpr(cast<BinaryOpExpr>(expr->getSecondOperand()));

		// Find constant and not constant in AddOpExpr or SubOpExpr.
		Expression* constSecOp;
		Expression* exprSecOp;
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
			Expression* result(getResult(SubOpExpr::create(
				expr->getFirstOperand(), constSecOp)));
			if (result) {
				// Result is Constant + anything.
				SubOpExpr* sub(SubOpExpr::create(result, exprSecOp));
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
				Expression* result(getResult(SubOpExpr::create(
					expr->getFirstOperand(), constSecOp)));
				if (result) {
					// Result is Constant + anything.
					AddOpExpr* add(AddOpExpr::create(result, exprSecOp));
					optimizeExpr(expr, add);
					return;
				}
			} else if (constSecOp->isEqualTo(subOpExpr->getSecondOperand())) {
				// Optimization like ConstInt/ConstFloat -
				// (anything - ConstInt/ConstFloat/anything).
				Expression* result(getResult(AddOpExpr::create(
					expr->getFirstOperand(), constSecOp)));
				if (result) {
					// Result is Constant - anything.
					SubOpExpr* sub(SubOpExpr::create(result, exprSecOp));
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
		AddOpExpr* addOpExpr(cast<AddOpExpr>(expr->getFirstOperand()));
		SubOpExpr* subOpExpr(cast<SubOpExpr>(expr->getFirstOperand()));
		BinaryOpExpr* binOpExpr(cast<BinaryOpExpr>(expr->getFirstOperand()));

		// Find constant and not constant in AddOpExpr or SubOpExpr.
		Expression* constSecOp;
		Expression* exprSecOp;
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
				Expression* result(getResult(SubOpExpr::create(constSecOp,
					expr->getFirstOperand())));
				if (result) {
					// Result is Constant + anything.
					AddOpExpr* add(AddOpExpr::create(result, exprSecOp));
					optimizeExpr(expr, add);
					return;
				}
			} else if (constSecOp->isEqualTo(addOpExpr->getSecondOperand())) {
				// Optimization like
				// (anything + ConstInt/ConstFloat/anything)
				// - ConstInt/ConstFloat.
				Expression* result(getResult(SubOpExpr::create(
					expr->getSecondOperand(), constSecOp)));
				if (result) {
					// Result is Anything - constant.
					SubOpExpr* sub(SubOpExpr::create(exprSecOp, result));
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
				Expression* result(getResult(SubOpExpr::create(constSecOp,
					expr->getSecondOperand())));
				if (result) {
					// Result is Constant - anything.
					SubOpExpr* sub(SubOpExpr::create(result, exprSecOp));
					optimizeExpr(expr, sub);
					return;
				}
			} else if (constSecOp->isEqualTo(subOpExpr->getSecondOperand())) {
				// Optimization like
				// (anything - ConstInt/ConstFloat)
				// - ConstInt/ConstFloat.
				Expression* result(getResult(AddOpExpr::create(constSecOp,
					expr->getSecondOperand())));
				if (result) {
					// Result is anything - Constant.
					SubOpExpr* sub(SubOpExpr::create(exprSecOp, result));
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
bool ThreeOperandsSubOptimizer::analyzeOpOperOp(Expression* &constant,
		Expression* &expr, BinaryOpExpr* exprToAnalyze) const {

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

void ThreeOperandsSubOptimizer::visit(LtOpExpr* expr) {
	OrderedAllVisitor::visit(expr);

	std::optional<ExprPair> exprPair(tryOptimizeExpressionWithRelationalOperator(expr));
	if (exprPair) {
		optimizeExpr(expr, LtOpExpr::create(exprPair->first, exprPair->second));
	}
}

void ThreeOperandsSubOptimizer::visit(LtEqOpExpr* expr) {
	OrderedAllVisitor::visit(expr);

	std::optional<ExprPair> exprPair(tryOptimizeExpressionWithRelationalOperator(expr));
	if (exprPair) {
		optimizeExpr(expr, LtEqOpExpr::create(exprPair->first, exprPair->second));
	}
}

void ThreeOperandsSubOptimizer::visit(GtOpExpr* expr) {
	OrderedAllVisitor::visit(expr);

	std::optional<ExprPair> exprPair(tryOptimizeExpressionWithRelationalOperator(expr));
	if (exprPair) {
		optimizeExpr(expr, GtOpExpr::create(exprPair->first, exprPair->second));
	}
}

void ThreeOperandsSubOptimizer::visit(GtEqOpExpr* expr) {
	OrderedAllVisitor::visit(expr);

	std::optional<ExprPair> exprPair(tryOptimizeExpressionWithRelationalOperator(expr));
	if (exprPair) {
		optimizeExpr(expr, GtEqOpExpr::create(exprPair->first, exprPair->second));
	}
}

void ThreeOperandsSubOptimizer::visit(EqOpExpr* expr) {
	OrderedAllVisitor::visit(expr);

	std::optional<ExprPair> exprPair(tryOptimizeExpressionWithRelationalOperator(expr));
	if (exprPair) {
		optimizeExpr(expr, EqOpExpr::create(exprPair->first, exprPair->second));
	}
}

void ThreeOperandsSubOptimizer::visit(NeqOpExpr* expr) {
	OrderedAllVisitor::visit(expr);

	std::optional<ExprPair> exprPair(tryOptimizeExpressionWithRelationalOperator(expr));
	if (exprPair) {
		optimizeExpr(expr, NeqOpExpr::create(exprPair->first, exprPair->second));
	}
}

void ThreeOperandsSubOptimizer::visit(BitXorOpExpr* expr) {
	OrderedAllVisitor::visit(expr);

	tryOptimizeBitXorOpWithRelationalOperator(expr);
}

void ThreeOperandsSubOptimizer::visit(OrOpExpr* expr) {
	OrderedAllVisitor::visit(expr);

	tryOptimizeOrOpExprWithRelOperators(expr);
}

/**
* @brief Optimizes expression like @code (var == ConstInt) || (var <= ConstInt)
*        @endcode to @code var <= ConstInt @endcode.
*
* @param[in] expr Expression to optimize.
*/
void ThreeOperandsSubOptimizer::tryOptimizeOrOpExprWithRelOperators(
		OrOpExpr* expr) {
	EqOpExpr* firstOpEqOp(cast<EqOpExpr>(expr->getFirstOperand()));
	LtEqOpExpr* secOpLtEqOp(cast<LtEqOpExpr>(expr->getSecondOperand()));
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

	ConstInt* firstOpConstInt(
		cast<ConstInt>(firstOpEqOp->getSecondOperand()));
	ConstInt* secOpConstInt(
		cast<ConstInt>(secOpLtEqOp->getSecondOperand()));

	if (!firstOpConstInt || !secOpConstInt) {
		// Operands doesn't have integer constants.
		return;
	}

	// Evaluate two ConstInt's and thank to result optimize or not.
	LtEqOpExpr* ltEqOpExpr(
		LtEqOpExpr::create(firstOpConstInt, secOpConstInt));
	ConstBool* constBool(
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
void ThreeOperandsSubOptimizer::tryOptimizeBitXorOpWithRelationalOperator(
		BitXorOpExpr* expr) {
	Expression* firstOp(expr->getFirstOperand());
	Expression* secOp(expr->getSecondOperand());

	// Expression like (a < 2) ^ True can be optimized to !(a < 2).
	NotOpExpr* notOpExpr = nullptr;
	if (isRelationalOperator(firstOp)) {
		ConstBool* constBoolSecOp(cast<ConstBool>(secOp));
		if (constBoolSecOp && constBoolSecOp->getValue()) {
			// ConstBool must be True.
			notOpExpr = NotOpExpr::create(firstOp);
		}
	} else if (isRelationalOperator(secOp) && isa<ConstBool>(firstOp)) {
		ConstBool* constBoolFirstOp(cast<ConstBool>(firstOp));
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
std::optional<ThreeOperandsSubOptimizer::ExprPair> ThreeOperandsSubOptimizer::
		tryOptimizeExpressionWithRelationalOperator(BinaryOpExpr* expr) {
	if (isConstFloatOrConstInt(expr->getSecondOperand())) {
		// Optimization like
		// (ConstInt/ConstFloat/anything + - ConstInt/ConstFloat/anything)
		// < ConstInt/ConstFloat.
		AddOpExpr* addOpExpr(cast<AddOpExpr>(expr->getFirstOperand()));
		SubOpExpr* subOpExpr(cast<SubOpExpr>(expr->getFirstOperand()));
		BinaryOpExpr* binOpExpr(cast<BinaryOpExpr>(expr->getFirstOperand()));

		// Find constant and not constant in AddOpExpr or SubOpExpr.
		Expression* constSecOp;
		Expression* exprSecOp;
		if (addOpExpr || subOpExpr) {
			if (!analyzeOpOperOp(constSecOp, exprSecOp, binOpExpr)) {
				// Something like (anything + - anything) < ConstInt/ConstFloat.
				// "anything" in both operands are not ConstInt/ConstFloat.
				return std::nullopt;
			};
		}
		if (addOpExpr) {
			// Optimization like
			// (ConstInt/ConstFloat + ConstInt/ConstFloat/anything)
			// < ConstInt/ConstFloat.
			Expression* result(getResult(SubOpExpr::create(
				expr->getSecondOperand(), constSecOp)));
			if (result) {
				// Result is anything relational operator Constant.
				return ExprPair(exprSecOp, result);
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
				Expression* result(getResult(AddOpExpr::create(
					expr->getSecondOperand(), constSecOp)));
				if (result) {
					// Result is anything relational operator Constant.
					return ExprPair(exprSecOp, result);
				}
			} else if (constSecOp->isEqualTo(subOpExpr->getFirstOperand())) {
				// Optimization like
				// (ConstInt/ConstFloat - anything)
				// < ConstInt/ConstFloat.
				Expression* result(getResult(SubOpExpr::create(
					expr->getSecondOperand(), constSecOp)));
				NegOpExpr* negOpExpr(NegOpExpr::create(exprSecOp));
				if (result) {
					// Result is anything(negOpExpr) relational operator Constant.
					return ExprPair(negOpExpr, result);
				}
			}
		}
	}
	return std::nullopt;
}

/**
* @brief Evaluate @a expr and return result.
*
* @param[in] expr Expression to evaluate.
*
* @return The result. If counting was not successful return the null pointer.
*/
Expression* ThreeOperandsSubOptimizer::getResult(Expression* expr) const {
	return arithmExprEvaluator->evaluate(expr);
}

} // namespace llvmir2hll
} // namespace retdec

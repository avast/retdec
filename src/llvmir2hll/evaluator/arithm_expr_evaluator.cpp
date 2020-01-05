/**
* @file src/llvmir2hll/evaluator/arithm_expr_evaluator.cpp
* @brief Implementation of ArithmExprEvaluator.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/evaluator/arithm_expr_evaluator.h"
#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/address_op_expr.h"
#include "retdec/llvmir2hll/ir/and_op_expr.h"
#include "retdec/llvmir2hll/ir/array_index_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_and_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_cast_expr.h"
#include "retdec/llvmir2hll/ir/bit_or_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_shl_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_shr_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_xor_op_expr.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/const_array.h"
#include "retdec/llvmir2hll/ir/const_null_pointer.h"
#include "retdec/llvmir2hll/ir/const_string.h"
#include "retdec/llvmir2hll/ir/const_struct.h"
#include "retdec/llvmir2hll/ir/const_symbol.h"
#include "retdec/llvmir2hll/ir/deref_op_expr.h"
#include "retdec/llvmir2hll/ir/div_op_expr.h"
#include "retdec/llvmir2hll/ir/eq_op_expr.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/ext_cast_expr.h"
#include "retdec/llvmir2hll/ir/fp_to_int_cast_expr.h"
#include "retdec/llvmir2hll/ir/gt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/gt_op_expr.h"
#include "retdec/llvmir2hll/ir/int_to_fp_cast_expr.h"
#include "retdec/llvmir2hll/ir/int_to_ptr_cast_expr.h"
#include "retdec/llvmir2hll/ir/lt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/lt_op_expr.h"
#include "retdec/llvmir2hll/ir/mod_op_expr.h"
#include "retdec/llvmir2hll/ir/mul_op_expr.h"
#include "retdec/llvmir2hll/ir/neg_op_expr.h"
#include "retdec/llvmir2hll/ir/neq_op_expr.h"
#include "retdec/llvmir2hll/ir/not_op_expr.h"
#include "retdec/llvmir2hll/ir/or_op_expr.h"
#include "retdec/llvmir2hll/ir/pointer_type.h"
#include "retdec/llvmir2hll/ir/ptr_to_int_cast_expr.h"
#include "retdec/llvmir2hll/ir/struct_index_op_expr.h"
#include "retdec/llvmir2hll/ir/sub_op_expr.h"
#include "retdec/llvmir2hll/ir/ternary_op_expr.h"
#include "retdec/llvmir2hll/ir/trunc_cast_expr.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {
namespace {

/**
* @brief Top and pop stack.
*
* @param[in, out] stack Stack to top and pop.
*
* @return Topped constant operand.
*/
Constant* topAndPopStack(ArithmExprEvaluator::ConstStack &stack) {
	ASSERT_MSG(!stack.empty(), "Signalizes not correctly evaluating.");
	Constant* constant(stack.top());
	stack.pop();
	return constant;
}

/**
* @brief Choose the first and the second operator from the @a stack and
*        return a @c ConstPair.
*
* @param[in, out] stack Stack with operands.
*
* @return A pair of constant operands.
*/
ArithmExprEvaluator::ConstPair getFirstAndSecondOpFromStack(
		ArithmExprEvaluator::ConstStack &stack) {
	// The second operand is on the top of the stack, so pop it first.
	Constant* second(topAndPopStack(stack));
	Constant* first(topAndPopStack(stack));
	return ArithmExprEvaluator::ConstPair(first, second);
}

/**
* @brief Clear the @a stack.
*
* @param[in, out] stack Stack to clear.
*/
void clearStack(ArithmExprEvaluator::ConstStack &stack) {
	// std::stack doesn't have clear method.
	stack = ArithmExprEvaluator::ConstStack();
}

} // anonymous namespace

/**
* @brief Evaluate an @a expr.
*
* @param[in] expr An expression to evaluation.
*
* @return If @a exr can be evaluated, returns evaluated @c Constant, otherwise
*         the null pointer.
*/
Constant* ArithmExprEvaluator::evaluate(Expression* expr) {
	return evaluate(expr, VarConstMap());
}

/**
* @brief Evaluate an @a expr.
*
* @param[in] expr An expression to evaluation.
* @param[in] varValues Map of constants to substitute the variables in @a expr.
*
* @return If @a exr can be evaluated, returns evaluated @c Constant, otherwise
*         the null pointer.
*/
Constant* ArithmExprEvaluator::evaluate(Expression* expr,
		const VarConstMap &varValues) {
	// Need to set stack and canBeEvaluated to initial state.
	clearStack(stackOfResults);
	canBeEvaluated = true;

	this->varValues = &varValues;
	expr->accept(this);
	return canBeEvaluated && !stackOfResults.empty() ? stackOfResults.top() :
		nullptr;
}

/**
* @brief Evaluate @a expr and return if result is @c bool.
*
* @param[in] expr An expression to evaluate.
* @param[in] varValues Map of constants to substitute the variables in @a expr.
*
* @return Bool value if the @a expr after evaluation is @c bool,
*         <tt>std::nullopt<bool>()</tt> otherwise.
*/
std::optional<bool> ArithmExprEvaluator::toBool(Expression* expr, VarConstMap
		varValues) {
	Constant* result(evaluate(expr, varValues));
	if (!result) {
		return std::nullopt;
	}

	if (ConstInt* constInt = cast<ConstInt>(result)) {
			return !constInt->isZero();
	} else if (ConstFloat* constFloat = cast<ConstFloat>(result)) {
		return !constFloat->isZero();
	} else if (ConstBool* constBool = cast<ConstBool>(result)) {
		return constBool->getValue();
	} else {
		return std::nullopt;
	}
}

void ArithmExprEvaluator::visit(AddressOpExpr* expr) {
	canBeEvaluated = false;
}

void ArithmExprEvaluator::visit(ArrayIndexOpExpr* expr) {
	canBeEvaluated = false;
}

void ArithmExprEvaluator::visit(StructIndexOpExpr* expr) {
	canBeEvaluated = false;
}

void ArithmExprEvaluator::visit(DerefOpExpr* expr) {
	canBeEvaluated = false;
}

void ArithmExprEvaluator::visit(NotOpExpr* expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		Constant* operand(getOperandForUnaryOpAndResolveTypes());
		resolveOpSpecifications(expr, operand);
		if (!canBeEvaluated) {
			return;
		}

		Constant* result;
		if (ConstInt* operandConstInt = cast<ConstInt>(operand)) {
			result = ConstBool::create(!operandConstInt->getValue());
		} else if (ConstFloat* operandConstFloat = cast<ConstFloat>(
				operand)) {
			result = ConstBool::create(operandConstFloat->isZero());
		} else if (ConstBool* operandConstBool = cast<ConstBool>(
				operand)) {
			result = ConstBool::create(!operandConstBool->getValue());
		} else {
			canBeEvaluated = false;
		}

		stackOfResults.push(result);
	}
}

void ArithmExprEvaluator::visit(NegOpExpr* expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		Constant* operand(getOperandForUnaryOpAndResolveTypes());
		resolveOpSpecifications(expr, operand);
		if (!canBeEvaluated) {
			return;
		}

		Constant* result;
		if (ConstInt* operandConstInt = cast<ConstInt>(operand)) {
			result = ConstInt::create(-operandConstInt->getValue());
		} else if (ConstFloat* operandConstFloat = cast<ConstFloat>(
				operand)) {
			llvm::APFloat apFloat = operandConstFloat->getValue();
			apFloat.changeSign();
			result = ConstFloat::create(apFloat);
		} else {
			canBeEvaluated = false;
		}

		stackOfResults.push(result);
	}
}

void ArithmExprEvaluator::visit(EqOpExpr* expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ConstPair constPair(getOperandsForBinaryOpAndResolveTypes());
		resolveOpSpecifications(expr, constPair);
		if (!canBeEvaluated) {
			return;
		}

		Constant* result;
		if (std::optional<ConstIntPair> constIntPair = castConstPair<ConstInt>(
				constPair)) {
			result = performOperationOverApInt(constIntPair, &llvm::APInt::eq);
		} else if (std::optional<ConstFloatPair> constFloatPair = castConstPair<
				ConstFloat>(constPair)) {
			result = ConstBool::create(
				performOperationOverApFloat(constFloatPair) ==
					llvm::APFloat::cmpEqual);
		} else if (std::optional<ConstBoolPair> constBoolPair = castConstPair<
				ConstBool>(constPair)) {
			result = ConstBool::create(constBoolPair->first->getValue() ==
				constBoolPair->second->getValue());
		} else {
			canBeEvaluated = false;
		}

		stackOfResults.push(result);
	}
}

void ArithmExprEvaluator::visit(NeqOpExpr* expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ConstPair constPair(getOperandsForBinaryOpAndResolveTypes());
		resolveOpSpecifications(expr, constPair);
		if (!canBeEvaluated) {
			return;
		}

		Constant* result;
		if (std::optional<ConstIntPair> constIntPair = castConstPair<ConstInt>(
				constPair)) {
			result = performOperationOverApInt(constIntPair, &llvm::APInt::ne);
		} else if (std::optional<ConstFloatPair> constFloatPair = castConstPair<
				ConstFloat>(constPair)) {
			result = ConstBool::create(
				performOperationOverApFloat(constFloatPair) !=
					llvm::APFloat::cmpEqual);
		} else if (std::optional<ConstBoolPair> constBoolPair = castConstPair<
				ConstBool>(constPair)) {
			result = ConstBool::create(constBoolPair->first->getValue() !=
				constBoolPair->second->getValue());
		} else {
			canBeEvaluated = false;
		}

		stackOfResults.push(result);
	}
}

void ArithmExprEvaluator::visit(LtEqOpExpr* expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ConstPair constPair(getOperandsForBinaryOpAndResolveTypes());
		resolveOpSpecifications(expr, constPair);
		if (!canBeEvaluated) {
			return;
		}

		Constant* result;
		if (std::optional<ConstIntPair> constIntPair = castConstPair<ConstInt>(
				constPair)) {
			result = performOperationOverApInt(constIntPair, &llvm::APInt::sle);
		} else if (std::optional<ConstFloatPair> constFloatPair = castConstPair<
				ConstFloat>(constPair)) {
			llvm::APFloat::cmpResult cmpResult = performOperationOverApFloat(
				constFloatPair);
			result = ConstBool::create(cmpResult == llvm::APFloat::cmpEqual ||
					cmpResult == llvm::APFloat::cmpLessThan);
		} else {
			canBeEvaluated = false;
		}

		stackOfResults.push(result);
	}
}

void ArithmExprEvaluator::visit(GtEqOpExpr* expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ConstPair constPair(getOperandsForBinaryOpAndResolveTypes());
		resolveOpSpecifications(expr, constPair);
		if (!canBeEvaluated) {
			return;
		}

		Constant* result;
		if (std::optional<ConstIntPair> constIntPair = castConstPair<ConstInt>(
				constPair)) {
			result = performOperationOverApInt(constIntPair, &llvm::APInt::sge);
		} else if (std::optional<ConstFloatPair> constFloatPair = castConstPair<
				ConstFloat>(constPair)) {
			llvm::APFloat::cmpResult cmpResult = performOperationOverApFloat(
				constFloatPair);
			result = ConstBool::create(cmpResult == llvm::APFloat::cmpEqual ||
					cmpResult == llvm::APFloat::cmpGreaterThan);
		} else {
			canBeEvaluated = false;
		}

		stackOfResults.push(result);
	}
}

void ArithmExprEvaluator::visit(LtOpExpr* expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ConstPair constPair(getOperandsForBinaryOpAndResolveTypes());
		resolveOpSpecifications(expr, constPair);
		if (!canBeEvaluated) {
			return;
		}

		Constant* result;
		if (std::optional<ConstIntPair> constIntPair = castConstPair<ConstInt>(
				constPair)) {
			result = performOperationOverApInt(constIntPair, &llvm::APInt::slt);
		} else if (std::optional<ConstFloatPair> constFloatPair = castConstPair<
				ConstFloat>(constPair)) {
			result = ConstBool::create(
				performOperationOverApFloat(constFloatPair) ==
					llvm::APFloat::cmpLessThan);
		} else {
			canBeEvaluated = false;
		}

		stackOfResults.push(result);
	}
}

void ArithmExprEvaluator::visit(GtOpExpr* expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ConstPair constPair(getOperandsForBinaryOpAndResolveTypes());
		resolveOpSpecifications(expr, constPair);
		if (!canBeEvaluated) {
			return;
		}

		Constant* result;
		if (std::optional<ConstIntPair> constIntPair = castConstPair<ConstInt>(
				constPair)) {
			result = performOperationOverApInt(constIntPair, &llvm::APInt::sgt);
		} else if (std::optional<ConstFloatPair> constFloatPair = castConstPair<
				ConstFloat>(constPair)) {
			result = ConstBool::create(
				performOperationOverApFloat(constFloatPair) ==
					llvm::APFloat::cmpGreaterThan);
		} else {
			canBeEvaluated = false;
		}

		stackOfResults.push(result);
	}
}

void ArithmExprEvaluator::visit(AddOpExpr* expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ConstPair constPair(getOperandsForBinaryOpAndResolveTypes());
		resolveOpSpecifications(expr, constPair);
		if (!canBeEvaluated) {
			return;
		}

		Constant* result;
		bool overflow = false;
		llvm::APFloat::opStatus opStatus = llvm::APFloat::opOK;
		if (std::optional<ConstIntPair> constIntPair = castConstPair<ConstInt>(
				constPair)) {
			result = performOperationOverApInt(constIntPair,
				&llvm::APInt::sadd_ov, overflow);
		} else if (std::optional<ConstFloatPair> constFloatPair = castConstPair<
				ConstFloat>(constPair)) {
			result = performOperationOverApFloat(constFloatPair,
				&llvm::APFloat::add, opStatus);
		} else {
			canBeEvaluated = false;
		}

		resolveOverflows(overflow, opStatus);
		stackOfResults.push(result);
	}
}

void ArithmExprEvaluator::visit(SubOpExpr* expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ConstPair constPair(getOperandsForBinaryOpAndResolveTypes());
		resolveOpSpecifications(expr, constPair);
		if (!canBeEvaluated) {
			return;
		}

		Constant* result;
		bool overflow = false;
		llvm::APFloat::opStatus opStatus = llvm::APFloat::opOK;
		if (std::optional<ConstIntPair> constIntPair = castConstPair<ConstInt>(
				constPair)) {
			result = performOperationOverApInt(constIntPair,
				&llvm::APInt::ssub_ov, overflow);
		} else if (std::optional<ConstFloatPair> constFloatPair = castConstPair<
				ConstFloat>(constPair)) {
			result = performOperationOverApFloat(constFloatPair,
				&llvm::APFloat::subtract, opStatus);
		} else {
			canBeEvaluated = false;
		}

		resolveOverflows(overflow, opStatus);
		stackOfResults.push(result);
	}
}

void ArithmExprEvaluator::visit(MulOpExpr* expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ConstPair constPair(getOperandsForBinaryOpAndResolveTypes());
		resolveOpSpecifications(expr, constPair);
		if (!canBeEvaluated) {
			return;
		}

		Constant* result;
		bool overflow = false;
		llvm::APFloat::opStatus opStatus = llvm::APFloat::opOK;
		if (std::optional<ConstIntPair> constIntPair = castConstPair<ConstInt>(
				constPair)) {
			result = performOperationOverApInt(constIntPair,
				&llvm::APInt::smul_ov, overflow);
		} else if (std::optional<ConstFloatPair> constFloatPair = castConstPair<
				ConstFloat>(constPair)) {
			result = performOperationOverApFloat(constFloatPair,
				&llvm::APFloat::multiply, opStatus);
		} else {
			canBeEvaluated = false;
		}

		resolveOverflows(overflow, opStatus);
		stackOfResults.push(result);
	}
}

void ArithmExprEvaluator::visit(ModOpExpr* expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ConstPair constPair(getOperandsForBinaryOpAndResolveTypes());
		resolveOpSpecifications(expr, constPair);
		if (!canBeEvaluated) {
			return;
		}

		Constant* result;
		llvm::APFloat::opStatus opStatus = llvm::APFloat::opOK;
		if (std::optional<ConstIntPair> constIntPair = castConstPair<ConstInt>(
				constPair)) {
			result = performOperationOverApInt(constIntPair, &llvm::APInt::srem);
		} else if (std::optional<ConstFloatPair> constFloatPair = castConstPair<
				ConstFloat>(constPair)) {
			result = performOperationOverApFloat(constFloatPair,
				&llvm::APFloat::mod, opStatus);
		} else {
			canBeEvaluated = false;
		}

		resolveOverflowForAPFloat(opStatus);
		stackOfResults.push(result);
	}
}

void ArithmExprEvaluator::visit(DivOpExpr* expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ConstPair constPair(getOperandsForBinaryOpAndResolveTypes());
		resolveOpSpecifications(expr, constPair);
		if (!canBeEvaluated) {
			return;
		}

		Constant* result;
		bool overflow = false;
		llvm::APFloat::opStatus opStatus = llvm::APFloat::opOK;
		if (std::optional<ConstIntPair> constIntPair = castConstPair<ConstInt>(
				constPair)) {
			result = performOperationOverApInt(constIntPair,
				&llvm::APInt::sdiv_ov, overflow);
		} else if (std::optional<ConstFloatPair> constFloatPair = castConstPair<
				ConstFloat>(constPair)) {
			result = performOperationOverApFloat(constFloatPair,
				&llvm::APFloat::divide, opStatus);
		} else {
			canBeEvaluated = false;
		}

		resolveOverflows(overflow, opStatus);
		stackOfResults.push(result);
	}
}

void ArithmExprEvaluator::visit(AndOpExpr* expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ConstPair constPair(getOperandsForBinaryOpAndResolveTypes());
		resolveOpSpecifications(expr, constPair);
		if (!canBeEvaluated) {
			return;
		}

		Constant* result;
		if (std::optional<ConstIntPair> constIntPair = castConstPair<ConstInt>(
				constPair)) {
			result = ConstBool::create(!constIntPair->first->isZero() &&
				!constIntPair->second->isZero());
		} else if (std::optional<ConstFloatPair> constFloatPair = castConstPair<
				ConstFloat>(constPair)) {
			result = ConstBool::create(!constFloatPair->first->isZero() &&
				!constFloatPair->second->isZero());
		} else if (std::optional<ConstBoolPair> constBoolPair = castConstPair<
				ConstBool>(constPair)) {
			result = ConstBool::create(constBoolPair->first->getValue() &&
				constBoolPair->second->getValue());
		} else {
			canBeEvaluated = false;
		}

		stackOfResults.push(result);
	}
}

void ArithmExprEvaluator::visit(OrOpExpr* expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ConstPair constPair(getOperandsForBinaryOpAndResolveTypes());
		resolveOpSpecifications(expr, constPair);
		if (!canBeEvaluated) {
			return;
		}

		Constant* result;
		if (std::optional<ConstIntPair> constIntPair = castConstPair<ConstInt>(
				constPair)) {
			result = ConstBool::create(!constIntPair->first->isZero() ||
				!constIntPair->second->isZero());
		} else if (std::optional<ConstFloatPair> constFloatPair = castConstPair<
				ConstFloat>(constPair)) {
			result = ConstBool::create(!constFloatPair->first->isZero() ||
				!constFloatPair->second->isZero());
		} else if (std::optional<ConstBoolPair> constBoolPair = castConstPair<
				ConstBool>(constPair)) {
			result = ConstBool::create(constBoolPair->first->getValue() ||
				constBoolPair->second->getValue());
		} else {
			canBeEvaluated = false;
		}

		stackOfResults.push(result);
	}
}

void ArithmExprEvaluator::visit(BitAndOpExpr* expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ConstPair constPair(getOperandsForBinaryOpAndResolveTypes());
		resolveOpSpecifications(expr, constPair);
		if (!canBeEvaluated) {
			return;
		}

		Constant* result;
		if (std::optional<ConstIntPair> constIntPair = castConstPair<ConstInt>(
				constPair)) {
			APSIntPair apsIntPair(getAPSIntsFromConstants(constIntPair));
			result = ConstInt::create(apsIntPair.first & apsIntPair.second);
		} else {
			canBeEvaluated = false;
		}

		stackOfResults.push(result);
	}
}

void ArithmExprEvaluator::visit(BitOrOpExpr* expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ConstPair constPair(getOperandsForBinaryOpAndResolveTypes());
		resolveOpSpecifications(expr, constPair);
		if (!canBeEvaluated) {
			return;
		}

		Constant* result;
		if (std::optional<ConstIntPair> constIntPair = castConstPair<ConstInt>(
				constPair)) {
			APSIntPair apsIntPair(getAPSIntsFromConstants(constIntPair));
			result = ConstInt::create(apsIntPair.first | apsIntPair.second);
		} else {
			canBeEvaluated = false;
		}

		stackOfResults.push(result);
	}
}

void ArithmExprEvaluator::visit(BitXorOpExpr* expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ConstPair constPair(getOperandsForBinaryOpAndResolveTypes());
		resolveOpSpecifications(expr, constPair);
		if (!canBeEvaluated) {
			return;
		}

		Constant* result;
		if (std::optional<ConstIntPair> constIntPair = castConstPair<ConstInt>(
				constPair)) {
			APSIntPair apsIntPair(getAPSIntsFromConstants(constIntPair));
			result = ConstInt::create(apsIntPair.first ^ apsIntPair.second);
		} else {
			canBeEvaluated = false;
		}

		stackOfResults.push(result);
	}
}

void ArithmExprEvaluator::visit(BitShlOpExpr* expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ConstPair constPair(getOperandsForBinaryOpAndResolveTypes());
		resolveOpSpecifications(expr, constPair);
		if (!canBeEvaluated) {
			return;
		}

		Constant* result;
		bool overflow = false;
		if (std::optional<ConstIntPair> constIntPair = castConstPair<ConstInt>(
				constPair)) {
			APSIntPair apsIntPair(getAPSIntsFromConstants(constIntPair));
			result = ConstInt::create(apsIntPair.first.sshl_ov(
				apsIntPair.second, overflow));
		} else {
			canBeEvaluated = false;
		}

		resolveOverflowForAPInt(overflow);
		stackOfResults.push(result);
	}
}

void ArithmExprEvaluator::visit(BitShrOpExpr* expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ConstPair constPair(getOperandsForBinaryOpAndResolveTypes());
		resolveOpSpecifications(expr, constPair);
		if (!canBeEvaluated) {
			return;
		}

		if (expr->isArithmetical()) {
			Constant* result;
			if (std::optional<ConstIntPair> constIntPair = castConstPair<ConstInt>(
					constPair)) {
				result = performOperationOverApInt(constIntPair,
					&llvm::APInt::ashr);
			} else {
				canBeEvaluated = false;
			}

			stackOfResults.push(result);
		} else if (expr->isLogical()) {
			Constant* result;
			if (std::optional<ConstIntPair> constIntPair = castConstPair<ConstInt>(
					constPair)) {
				result = performOperationOverApInt(constIntPair,
					&llvm::APInt::lshr);
			} else {
				canBeEvaluated = false;
			}

			stackOfResults.push(result);
		}
	}
}

void ArithmExprEvaluator::visit(TernaryOpExpr* expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		Constant* falseValue(topAndPopStack(stackOfResults));
		Constant* trueValue(topAndPopStack(stackOfResults));
		Constant* condition(topAndPopStack(stackOfResults));

		bool condResult(true);
		if (ConstInt* condConstInt = cast<ConstInt>(condition)) {
			condResult = !condConstInt->isZero();
		} else if (ConstFloat* condConstFloat = cast<ConstFloat>(
				condition)) {
			condResult = !condConstFloat->isZero();
		} else if (ConstBool* condConstBool = cast<ConstBool>(condition)) {
			condResult = condConstBool->getValue();
		} else {
			canBeEvaluated = false;
		}

		stackOfResults.push(condResult ? trueValue : falseValue);
	}
}

void ArithmExprEvaluator::visit(CallExpr* expr) {
	canBeEvaluated = false;
}

void ArithmExprEvaluator::visit(BitCastExpr* expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		Constant* constant(topAndPopStack(stackOfResults));
		resolveCast(expr, constant);
		stackOfResults.push(constant);
	}
}

void ArithmExprEvaluator::visit(ExtCastExpr* expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		Constant* constant(topAndPopStack(stackOfResults));
		resolveCast(expr, constant);
		stackOfResults.push(constant);
	}
}

void ArithmExprEvaluator::visit(TruncCastExpr* expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		Constant* constant(topAndPopStack(stackOfResults));
		resolveCast(expr, constant);
		stackOfResults.push(constant);
	}
}

void ArithmExprEvaluator::visit(FPToIntCastExpr* expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		Constant* constant(topAndPopStack(stackOfResults));
		resolveCast(expr, constant);
		stackOfResults.push(constant);
	}
}

void ArithmExprEvaluator::visit(IntToFPCastExpr* expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		Constant* constant(topAndPopStack(stackOfResults));
		resolveCast(expr, constant);
		stackOfResults.push(constant);
	}
}

void ArithmExprEvaluator::visit(IntToPtrCastExpr* expr) {
	canBeEvaluated = false;
}

void ArithmExprEvaluator::visit(PtrToIntCastExpr* expr) {
	canBeEvaluated = false;
}

void ArithmExprEvaluator::visit(ConstBool* constant) {
	stackOfResults.push(constant);
}

void ArithmExprEvaluator::visit(ConstFloat* constant) {
	stackOfResults.push(constant);
}

void ArithmExprEvaluator::visit(ConstInt* constant) {
	stackOfResults.push(constant);
}

void ArithmExprEvaluator::visit(ConstSymbol* constant) {
	stackOfResults.push(constant->getValue());
}

void ArithmExprEvaluator::visit(ConstNullPointer* constant) {
	canBeEvaluated = false;
}

void ArithmExprEvaluator::visit(ConstString* constant) {
	canBeEvaluated = false;
}

void ArithmExprEvaluator::visit(ConstArray* constant) {
	canBeEvaluated = false;
}

void ArithmExprEvaluator::visit(ConstStruct* constant) {
	canBeEvaluated = false;
}

void ArithmExprEvaluator::visit(Variable* var) {
	auto it = varValues->find(var);
	if (it != varValues->end()) {
		stackOfResults.push(it->second);
	} else {
		canBeEvaluated = false;
	}
}

void ArithmExprEvaluator::resolveTypesUnaryOp(Constant* &operand) {}

void ArithmExprEvaluator::resolveTypesBinaryOp(ConstPair &constPair) {}

void ArithmExprEvaluator::resolveOpSpecifications(AddOpExpr* expr,
	ConstPair &constPair) {}

void ArithmExprEvaluator::resolveOpSpecifications(AndOpExpr* expr,
	ConstPair &constPair) {}

void ArithmExprEvaluator::resolveOpSpecifications(BitAndOpExpr* expr,
	ConstPair &constPair) {}

void ArithmExprEvaluator::resolveOpSpecifications(BitOrOpExpr* expr,
	ConstPair &constPair) {}

void ArithmExprEvaluator::resolveOpSpecifications(BitShlOpExpr* expr,
	ConstPair &constPair) {}

void ArithmExprEvaluator::resolveOpSpecifications(BitShrOpExpr* expr,
	ConstPair &constPair) {}

void ArithmExprEvaluator::resolveOpSpecifications(BitXorOpExpr* expr,
	ConstPair &constPair) {}

void ArithmExprEvaluator::resolveOpSpecifications(DivOpExpr* expr,
	ConstPair &constPair) {}

void ArithmExprEvaluator::resolveOpSpecifications(EqOpExpr* expr,
	ConstPair &constPair) {}

void ArithmExprEvaluator::resolveOpSpecifications(GtOpExpr* expr,
	ConstPair &constPair) {}

void ArithmExprEvaluator::resolveOpSpecifications(GtEqOpExpr* expr,
	ConstPair &constPair) {}

void ArithmExprEvaluator::resolveOpSpecifications(LtEqOpExpr* expr,
	ConstPair &constPair) {}

void ArithmExprEvaluator::resolveOpSpecifications(LtOpExpr* expr,
	ConstPair &constPair) {}

void ArithmExprEvaluator::resolveOpSpecifications(ModOpExpr* expr,
	ConstPair &constPair) {}

void ArithmExprEvaluator::resolveOpSpecifications(MulOpExpr* expr,
	ConstPair &constPair) {}

void ArithmExprEvaluator::resolveOpSpecifications(NegOpExpr* expr,
	Constant* &constant) {}

void ArithmExprEvaluator::resolveOpSpecifications(NeqOpExpr* expr,
	ConstPair &constPair) {}

void ArithmExprEvaluator::resolveOpSpecifications(NotOpExpr* expr,
	Constant* &constant) {}

void ArithmExprEvaluator::resolveOpSpecifications(OrOpExpr* expr,
	ConstPair &constPair) {}

void ArithmExprEvaluator::resolveOpSpecifications(SubOpExpr* expr,
	ConstPair &constPair) {}

void ArithmExprEvaluator::resolveCast(BitCastExpr* expr,
	Constant* &constant) {}

void ArithmExprEvaluator::resolveCast(ExtCastExpr* expr,
	Constant* &constant) {}

void ArithmExprEvaluator::resolveCast(FPToIntCastExpr* expr,
	Constant* &constant) {}

void ArithmExprEvaluator::resolveCast(IntToFPCastExpr* expr,
	Constant* &constant) {}

void ArithmExprEvaluator::resolveCast(TruncCastExpr* expr,
	Constant* &constant) {}

void ArithmExprEvaluator::resolveOverflowForAPInt(bool overflow) {}

void ArithmExprEvaluator::resolveOverflowForAPFloat(llvm::APFloat::opStatus
	opStatus) {}

/**
* @brief Get operand from @c stackOfResults and call resolve types method that
*        is implemented in sub-evaluators.
*
* @return Constant operand after types corrections.
*/
Constant* ArithmExprEvaluator::getOperandForUnaryOpAndResolveTypes() {
	Constant* operand(topAndPopStack(stackOfResults));
	resolveTypesUnaryOp(operand);
	return operand;
}

/**
* @brief Get operands from @c stackOfResults and call resolve types method that
*        is implemented in sub-evaluators.
*
* @return A pair of constant operands after types corrections.
*/
ArithmExprEvaluator::ConstPair ArithmExprEvaluator::
		getOperandsForBinaryOpAndResolveTypes() {
	ConstPair constPair(getFirstAndSecondOpFromStack(stackOfResults));
	resolveTypesBinaryOp(constPair);
	return constPair;
}

/**
* @brief Casts the constants in @a constPair to the given type.
*
* @tparam ConstType Type of the constants after the cast.
*
* @return A pair of casted constants if the cast was correct, @c std::nullopt
*         otherwise.
*/
// template<typename ConstType>
// std::optional<std::pair<ConstType*, ConstType*>> ArithmExprEvaluator::
// 		castConstPair(const ConstPair &constPair) {
// 	ConstType* firstConst(cast<ConstType>(constPair.first));
// 	ConstType* secConst(cast<ConstType>(constPair.second));
// 	if (!firstConst || !secConst) {
// 		return std::nullopt;
// 	} else {
// 		return std::make_pair(firstConst, secConst);
// 	}
// }

/**
* @brief Perform the operation specified by @a op on the first and the
*        second operand in @a constIntPair.
*
* @a op are functions with prototype like:
* @code
* APInt sadd_ov(const APInt &RHS,
* bool &Overflow) const.
* @endcode
*
* @param[in] constIntPair A pair of @c ConstInt operands.
* @param[in] op Operation to do on @a constIntPair operands.
* @param[out] overflow Overflow status of operation.
*
* @return Result of operation.
*/
ConstInt* ArithmExprEvaluator::performOperationOverApInt(
		const std::optional<ConstIntPair> &constIntPair, LLVMAPIntAPIntBoolOp op,
		bool &overflow) {
	APSIntPair apsIntPair(getAPSIntsFromConstants(constIntPair));
	return ConstInt::create((apsIntPair.first.*op)(apsIntPair.second,
		overflow), apsIntPair.first.isSigned());
}

/**
* @brief Perform the operation specified by @a op on the first and the
*        second operand in @a constIntPair.
*
* @a op are functions with prototype like:
* @code
* APInt And(const APInt &RHS) const;
* @endcode
*
* @param[in] constIntPair A pair of @c ConstInt operands.
* @param[in] op Operation to do on @a constIntPair operands.
*
* @return Result of operation.
*/
ConstInt* ArithmExprEvaluator::performOperationOverApInt(
		const std::optional<ConstIntPair> &constIntPair, LLVMAPIntAPIntOp op) {
	APSIntPair apsIntPair(getAPSIntsFromConstants(constIntPair));
	return ConstInt::create((apsIntPair.first.*op)(apsIntPair.second),
		apsIntPair.first.isSigned());
}

/**
* @brief Perform the operation specified by @a op on the first and the
*        second operand in @a constIntPair.
*
* @a op are functions with prototype like:
* @code
* bool sgt(uint64_t RHS) const;
* @endcode
*
* @param[in] constIntPair A pair of @c ConstInt operands.
* @param[in] op Operation to do on @a constIntPair operands.
*
* @return Result of operation.
*/
ConstBool* ArithmExprEvaluator::performOperationOverApInt(
		const std::optional<ConstIntPair> &constIntPair, LLVMBoolAPIntOp op) {
	APSIntPair apsIntPair(getAPSIntsFromConstants(constIntPair));
	return ConstBool::create((apsIntPair.first.*op)(apsIntPair.second));
}

/**
* @brief Perform the compare operation on the first and the second operand in
*        @a constFloatPair.
*
* @param[in] constFloatPair A pair of @c ConstFloat operands.
*
* @return Result of operation.
*/
llvm::APFloat::cmpResult ArithmExprEvaluator::performOperationOverApFloat(
		const std::optional<ConstFloatPair> &constFloatPair) {
	APFloatPair apFloatPair(getAPFloatsFromConstants(constFloatPair));
	return apFloatPair.first.compare(apFloatPair.second);
}

/**
* @brief Perform the operation specified by @a op on the first and the
*        second operand in @a constFloatPair.
*
* @a op are functions with prototype like:
* @code
* opStatus add(const APFloat &, roundingMode);
* @endcode
*
* @param[in] constFloatPair A pair of @c ConstFloat operands.
* @param[in] op Operation to do on @a constFloatPair operands.
* @param[out] status Status of success of operation.
*
* @return Result of operation.
*/
ConstFloat* ArithmExprEvaluator::performOperationOverApFloat(
		const std::optional<ConstFloatPair> &constFloatPair, LLVMAPFloatOp op, llvm::
		APFloat::opStatus &status) {
	APFloatPair apFloatPair(getAPFloatsFromConstants(constFloatPair));
	status = ((apFloatPair.first).*op)(apFloatPair.second, llvm::APFloat::
		rmNearestTiesToEven);
	return ConstFloat::create(apFloatPair.first);
}

/**
* @brief An overload of @c performOperationOverApFloat() when the operation has
*        no rounding mode.
*/
ConstFloat* ArithmExprEvaluator::performOperationOverApFloat(
		const std::optional<ConstFloatPair> &constFloatPair, LLVMAPFloatOpNoRounding op,
		llvm::APFloat::opStatus &status) {
	APFloatPair apFloatPair(getAPFloatsFromConstants(constFloatPair));
	status = ((apFloatPair.first).*op)(apFloatPair.second);
	return ConstFloat::create(apFloatPair.first);
}

/**
* @brief Create @c APSIntPair from @a constIntPair and return it.
*
* @param[in] constIntPair A pair of @c ConstInt.
*
* @return Created pair of @c llvm::APSInt.
*/
ArithmExprEvaluator::APSIntPair ArithmExprEvaluator::getAPSIntsFromConstants(
		const std::optional<ConstIntPair> &constIntPair) {
	return APSIntPair(constIntPair->first->getValue(),
		constIntPair->second->getValue());
}

/**
* @brief Create @c APFloatPair from @a constFloatPair and return it.
*
* @param[in] constFloatPair A pair of @c ConstFloat.
*
* @return Created pair of @c llvm::APFloat.
*/
ArithmExprEvaluator::APFloatPair ArithmExprEvaluator::getAPFloatsFromConstants(
		const std::optional<ConstFloatPair> &constFloatPair) {
	return APFloatPair(constFloatPair->first->getValue(),
		constFloatPair->second->getValue());
}

/**
* @brief Call resolve methods for overflow.
*
* @param[in] overflow Overflow status after operation on @c llvm::APInt.
* @param[in] opStatus Status after operation on @c llvm::APFloat.
*/
void ArithmExprEvaluator::resolveOverflows(bool overflow,
		llvm::APFloat::opStatus opStatus) {
	resolveOverflowForAPFloat(opStatus);
	resolveOverflowForAPInt(overflow);
}

/**
* @brief Return if @a constant is a @c ConstInt or a @c ConstFloat zero.
*
* @param[in] constant A constant to check.
*
* @return If @a constant is @c ConstInt or @c ConstFloat zero.
*/
bool ArithmExprEvaluator::isConstantZero(Constant* constant) {
	ConstInt* secConstInt(cast<ConstInt>(constant));
	ConstFloat* secConstFloat(cast<ConstFloat>(constant));
	return (secConstInt && secConstInt->isZero()) ||
			(secConstFloat && secConstFloat->isZero());
}

} // namespace llvmir2hll
} // namespace retdec

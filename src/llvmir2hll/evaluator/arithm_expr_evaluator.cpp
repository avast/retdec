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
ShPtr<Constant> topAndPopStack(ArithmExprEvaluator::ConstStack &stack) {
	ASSERT_MSG(!stack.empty(), "Signalizes not correctly evaluating.");
	ShPtr<Constant> constant(stack.top());
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
	ShPtr<Constant> second(topAndPopStack(stack));
	ShPtr<Constant> first(topAndPopStack(stack));
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
* @brief Constructs the ArithmExprEvaluator.
*
* Use create() to create instances.
*/
ArithmExprEvaluator::ArithmExprEvaluator() : canBeEvaluated(true) {}

/**
* @brief Destructor.
*/
ArithmExprEvaluator::~ArithmExprEvaluator() {}

/**
* @brief Evaluate an @a expr.
*
* @param[in] expr An expression to evaluation.
*
* @return If @a exr can be evaluated, returns evaluated @c Constant, otherwise
*         the null pointer.
*/
ShPtr<Constant> ArithmExprEvaluator::evaluate(ShPtr<Expression> expr) {
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
ShPtr<Constant> ArithmExprEvaluator::evaluate(ShPtr<Expression> expr,
		const VarConstMap &varValues) {
	// Need to set stack and canBeEvaluated to initial state.
	clearStack(stackOfResults);
	canBeEvaluated = true;

	this->varValues = &varValues;
	expr->accept(this);
	return canBeEvaluated && !stackOfResults.empty() ? stackOfResults.top() :
		ShPtr<Constant>();
}

/**
* @brief Evaluate @a expr and return if result is @c bool.
*
* @param[in] expr An expression to evaluate.
* @param[in] varValues Map of constants to substitute the variables in @a expr.
*
* @return <tt>Just(bool)</tt> if the @a expr after evaluation is @c bool,
*         <tt>Nothing<bool>()</tt> otherwise.
*/
Maybe<bool> ArithmExprEvaluator::toBool(ShPtr<Expression> expr, VarConstMap
		varValues) {
	ShPtr<Constant> result(evaluate(expr, varValues));
	if (!result) {
		return Nothing<bool>();
	}

	if (ShPtr<ConstInt> constInt = cast<ConstInt>(result)) {
			return Just(!constInt->isZero());
	} else if (ShPtr<ConstFloat> constFloat = cast<ConstFloat>(result)) {
		return Just(!constFloat->isZero());
	} else if (ShPtr<ConstBool> constBool = cast<ConstBool>(result)) {
		return Just(constBool->getValue());
	} else {
		return Nothing<bool>();
	}
}

void ArithmExprEvaluator::visit(ShPtr<AddressOpExpr> expr) {
	canBeEvaluated = false;
}

void ArithmExprEvaluator::visit(ShPtr<ArrayIndexOpExpr> expr) {
	canBeEvaluated = false;
}

void ArithmExprEvaluator::visit(ShPtr<StructIndexOpExpr> expr) {
	canBeEvaluated = false;
}

void ArithmExprEvaluator::visit(ShPtr<DerefOpExpr> expr) {
	canBeEvaluated = false;
}

void ArithmExprEvaluator::visit(ShPtr<NotOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ShPtr<Constant> operand(getOperandForUnaryOpAndResolveTypes());
		resolveOpSpecifications(expr, operand);
		if (!canBeEvaluated) {
			return;
		}

		ShPtr<Constant> result;
		if (ShPtr<ConstInt> operandConstInt = cast<ConstInt>(operand)) {
			result = ConstBool::create(!operandConstInt->getValue());
		} else if (ShPtr<ConstFloat> operandConstFloat = cast<ConstFloat>(
				operand)) {
			result = ConstBool::create(operandConstFloat->isZero());
		} else if (ShPtr<ConstBool> operandConstBool = cast<ConstBool>(
				operand)) {
			result = ConstBool::create(!operandConstBool->getValue());
		} else {
			canBeEvaluated = false;
		}

		stackOfResults.push(result);
	}
}

void ArithmExprEvaluator::visit(ShPtr<NegOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ShPtr<Constant> operand(getOperandForUnaryOpAndResolveTypes());
		resolveOpSpecifications(expr, operand);
		if (!canBeEvaluated) {
			return;
		}

		ShPtr<Constant> result;
		if (ShPtr<ConstInt> operandConstInt = cast<ConstInt>(operand)) {
			result = ConstInt::create(-operandConstInt->getValue());
		} else if (ShPtr<ConstFloat> operandConstFloat = cast<ConstFloat>(
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

void ArithmExprEvaluator::visit(ShPtr<EqOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ConstPair constPair(getOperandsForBinaryOpAndResolveTypes());
		resolveOpSpecifications(expr, constPair);
		if (!canBeEvaluated) {
			return;
		}

		ShPtr<Constant> result;
		if (Maybe<ConstIntPair> constIntPair = castConstPair<ConstInt>(
				constPair)) {
			result = performOperationOverApInt(constIntPair, &llvm::APInt::eq);
		} else if (Maybe<ConstFloatPair> constFloatPair = castConstPair<
				ConstFloat>(constPair)) {
			result = ConstBool::create(
				performOperationOverApFloat(constFloatPair) ==
					llvm::APFloat::cmpEqual);
		} else if (Maybe<ConstBoolPair> constBoolPair = castConstPair<
				ConstBool>(constPair)) {
			result = ConstBool::create(constBoolPair->first->getValue() ==
				constBoolPair->second->getValue());
		} else {
			canBeEvaluated = false;
		}

		stackOfResults.push(result);
	}
}

void ArithmExprEvaluator::visit(ShPtr<NeqOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ConstPair constPair(getOperandsForBinaryOpAndResolveTypes());
		resolveOpSpecifications(expr, constPair);
		if (!canBeEvaluated) {
			return;
		}

		ShPtr<Constant> result;
		if (Maybe<ConstIntPair> constIntPair = castConstPair<ConstInt>(
				constPair)) {
			result = performOperationOverApInt(constIntPair, &llvm::APInt::ne);
		} else if (Maybe<ConstFloatPair> constFloatPair = castConstPair<
				ConstFloat>(constPair)) {
			result = ConstBool::create(
				performOperationOverApFloat(constFloatPair) !=
					llvm::APFloat::cmpEqual);
		} else if (Maybe<ConstBoolPair> constBoolPair = castConstPair<
				ConstBool>(constPair)) {
			result = ConstBool::create(constBoolPair->first->getValue() !=
				constBoolPair->second->getValue());
		} else {
			canBeEvaluated = false;
		}

		stackOfResults.push(result);
	}
}

void ArithmExprEvaluator::visit(ShPtr<LtEqOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ConstPair constPair(getOperandsForBinaryOpAndResolveTypes());
		resolveOpSpecifications(expr, constPair);
		if (!canBeEvaluated) {
			return;
		}

		ShPtr<Constant> result;
		if (Maybe<ConstIntPair> constIntPair = castConstPair<ConstInt>(
				constPair)) {
			result = performOperationOverApInt(constIntPair, &llvm::APInt::sle);
		} else if (Maybe<ConstFloatPair> constFloatPair = castConstPair<
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

void ArithmExprEvaluator::visit(ShPtr<GtEqOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ConstPair constPair(getOperandsForBinaryOpAndResolveTypes());
		resolveOpSpecifications(expr, constPair);
		if (!canBeEvaluated) {
			return;
		}

		ShPtr<Constant> result;
		if (Maybe<ConstIntPair> constIntPair = castConstPair<ConstInt>(
				constPair)) {
			result = performOperationOverApInt(constIntPair, &llvm::APInt::sge);
		} else if (Maybe<ConstFloatPair> constFloatPair = castConstPair<
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

void ArithmExprEvaluator::visit(ShPtr<LtOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ConstPair constPair(getOperandsForBinaryOpAndResolveTypes());
		resolveOpSpecifications(expr, constPair);
		if (!canBeEvaluated) {
			return;
		}

		ShPtr<Constant> result;
		if (Maybe<ConstIntPair> constIntPair = castConstPair<ConstInt>(
				constPair)) {
			result = performOperationOverApInt(constIntPair, &llvm::APInt::slt);
		} else if (Maybe<ConstFloatPair> constFloatPair = castConstPair<
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

void ArithmExprEvaluator::visit(ShPtr<GtOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ConstPair constPair(getOperandsForBinaryOpAndResolveTypes());
		resolveOpSpecifications(expr, constPair);
		if (!canBeEvaluated) {
			return;
		}

		ShPtr<Constant> result;
		if (Maybe<ConstIntPair> constIntPair = castConstPair<ConstInt>(
				constPair)) {
			result = performOperationOverApInt(constIntPair, &llvm::APInt::sgt);
		} else if (Maybe<ConstFloatPair> constFloatPair = castConstPair<
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

void ArithmExprEvaluator::visit(ShPtr<AddOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ConstPair constPair(getOperandsForBinaryOpAndResolveTypes());
		resolveOpSpecifications(expr, constPair);
		if (!canBeEvaluated) {
			return;
		}

		ShPtr<Constant> result;
		bool overflow = false;
		llvm::APFloat::opStatus opStatus = llvm::APFloat::opOK;
		if (Maybe<ConstIntPair> constIntPair = castConstPair<ConstInt>(
				constPair)) {
			result = performOperationOverApInt(constIntPair,
				&llvm::APInt::sadd_ov, overflow);
		} else if (Maybe<ConstFloatPair> constFloatPair = castConstPair<
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

void ArithmExprEvaluator::visit(ShPtr<SubOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ConstPair constPair(getOperandsForBinaryOpAndResolveTypes());
		resolveOpSpecifications(expr, constPair);
		if (!canBeEvaluated) {
			return;
		}

		ShPtr<Constant> result;
		bool overflow = false;
		llvm::APFloat::opStatus opStatus = llvm::APFloat::opOK;
		if (Maybe<ConstIntPair> constIntPair = castConstPair<ConstInt>(
				constPair)) {
			result = performOperationOverApInt(constIntPair,
				&llvm::APInt::ssub_ov, overflow);
		} else if (Maybe<ConstFloatPair> constFloatPair = castConstPair<
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

void ArithmExprEvaluator::visit(ShPtr<MulOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ConstPair constPair(getOperandsForBinaryOpAndResolveTypes());
		resolveOpSpecifications(expr, constPair);
		if (!canBeEvaluated) {
			return;
		}

		ShPtr<Constant> result;
		bool overflow = false;
		llvm::APFloat::opStatus opStatus = llvm::APFloat::opOK;
		if (Maybe<ConstIntPair> constIntPair = castConstPair<ConstInt>(
				constPair)) {
			result = performOperationOverApInt(constIntPair,
				&llvm::APInt::smul_ov, overflow);
		} else if (Maybe<ConstFloatPair> constFloatPair = castConstPair<
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

void ArithmExprEvaluator::visit(ShPtr<ModOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ConstPair constPair(getOperandsForBinaryOpAndResolveTypes());
		resolveOpSpecifications(expr, constPair);
		if (!canBeEvaluated) {
			return;
		}

		ShPtr<Constant> result;
		llvm::APFloat::opStatus opStatus = llvm::APFloat::opOK;
		if (Maybe<ConstIntPair> constIntPair = castConstPair<ConstInt>(
				constPair)) {
			result = performOperationOverApInt(constIntPair, &llvm::APInt::srem);
		} else if (Maybe<ConstFloatPair> constFloatPair = castConstPair<
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

void ArithmExprEvaluator::visit(ShPtr<DivOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ConstPair constPair(getOperandsForBinaryOpAndResolveTypes());
		resolveOpSpecifications(expr, constPair);
		if (!canBeEvaluated) {
			return;
		}

		ShPtr<Constant> result;
		bool overflow = false;
		llvm::APFloat::opStatus opStatus = llvm::APFloat::opOK;
		if (Maybe<ConstIntPair> constIntPair = castConstPair<ConstInt>(
				constPair)) {
			result = performOperationOverApInt(constIntPair,
				&llvm::APInt::sdiv_ov, overflow);
		} else if (Maybe<ConstFloatPair> constFloatPair = castConstPair<
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

void ArithmExprEvaluator::visit(ShPtr<AndOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ConstPair constPair(getOperandsForBinaryOpAndResolveTypes());
		resolveOpSpecifications(expr, constPair);
		if (!canBeEvaluated) {
			return;
		}

		ShPtr<Constant> result;
		if (Maybe<ConstIntPair> constIntPair = castConstPair<ConstInt>(
				constPair)) {
			result = ConstBool::create(!constIntPair->first->isZero() &&
				!constIntPair->second->isZero());
		} else if (Maybe<ConstFloatPair> constFloatPair = castConstPair<
				ConstFloat>(constPair)) {
			result = ConstBool::create(!constFloatPair->first->isZero() &&
				!constFloatPair->second->isZero());
		} else if (Maybe<ConstBoolPair> constBoolPair = castConstPair<
				ConstBool>(constPair)) {
			result = ConstBool::create(constBoolPair->first->getValue() &&
				constBoolPair->second->getValue());
		} else {
			canBeEvaluated = false;
		}

		stackOfResults.push(result);
	}
}

void ArithmExprEvaluator::visit(ShPtr<OrOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ConstPair constPair(getOperandsForBinaryOpAndResolveTypes());
		resolveOpSpecifications(expr, constPair);
		if (!canBeEvaluated) {
			return;
		}

		ShPtr<Constant> result;
		if (Maybe<ConstIntPair> constIntPair = castConstPair<ConstInt>(
				constPair)) {
			result = ConstBool::create(!constIntPair->first->isZero() ||
				!constIntPair->second->isZero());
		} else if (Maybe<ConstFloatPair> constFloatPair = castConstPair<
				ConstFloat>(constPair)) {
			result = ConstBool::create(!constFloatPair->first->isZero() ||
				!constFloatPair->second->isZero());
		} else if (Maybe<ConstBoolPair> constBoolPair = castConstPair<
				ConstBool>(constPair)) {
			result = ConstBool::create(constBoolPair->first->getValue() ||
				constBoolPair->second->getValue());
		} else {
			canBeEvaluated = false;
		}

		stackOfResults.push(result);
	}
}

void ArithmExprEvaluator::visit(ShPtr<BitAndOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ConstPair constPair(getOperandsForBinaryOpAndResolveTypes());
		resolveOpSpecifications(expr, constPair);
		if (!canBeEvaluated) {
			return;
		}

		ShPtr<Constant> result;
		if (Maybe<ConstIntPair> constIntPair = castConstPair<ConstInt>(
				constPair)) {
			result = performOperationOverApInt(constIntPair, &llvm::APInt::And);
		} else {
			canBeEvaluated = false;
		}

		stackOfResults.push(result);
	}
}

void ArithmExprEvaluator::visit(ShPtr<BitOrOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ConstPair constPair(getOperandsForBinaryOpAndResolveTypes());
		resolveOpSpecifications(expr, constPair);
		if (!canBeEvaluated) {
			return;
		}

		ShPtr<Constant> result;
		if (Maybe<ConstIntPair> constIntPair = castConstPair<ConstInt>(
				constPair)) {
			result = performOperationOverApInt(constIntPair, &llvm::APInt::Or);
		} else {
			canBeEvaluated = false;
		}

		stackOfResults.push(result);
	}
}

void ArithmExprEvaluator::visit(ShPtr<BitXorOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ConstPair constPair(getOperandsForBinaryOpAndResolveTypes());
		resolveOpSpecifications(expr, constPair);
		if (!canBeEvaluated) {
			return;
		}

		ShPtr<Constant> result;
		if (Maybe<ConstIntPair> constIntPair = castConstPair<ConstInt>(
				constPair)) {
			result = performOperationOverApInt(constIntPair, &llvm::APInt::Xor);
		} else {
			canBeEvaluated = false;
		}

		stackOfResults.push(result);
	}
}

void ArithmExprEvaluator::visit(ShPtr<BitShlOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ConstPair constPair(getOperandsForBinaryOpAndResolveTypes());
		resolveOpSpecifications(expr, constPair);
		if (!canBeEvaluated) {
			return;
		}

		ShPtr<Constant> result;
		bool overflow = false;
		if (Maybe<ConstIntPair> constIntPair = castConstPair<ConstInt>(
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

void ArithmExprEvaluator::visit(ShPtr<BitShrOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ConstPair constPair(getOperandsForBinaryOpAndResolveTypes());
		resolveOpSpecifications(expr, constPair);
		if (!canBeEvaluated) {
			return;
		}

		if (expr->isArithmetical()) {
			ShPtr<Constant> result;
			if (Maybe<ConstIntPair> constIntPair = castConstPair<ConstInt>(
					constPair)) {
				result = performOperationOverApInt(constIntPair,
					&llvm::APInt::ashr);
			} else {
				canBeEvaluated = false;
			}

			stackOfResults.push(result);
		} else if (expr->isLogical()) {
			ShPtr<Constant> result;
			if (Maybe<ConstIntPair> constIntPair = castConstPair<ConstInt>(
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

void ArithmExprEvaluator::visit(ShPtr<TernaryOpExpr> expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ShPtr<Constant> falseValue(topAndPopStack(stackOfResults));
		ShPtr<Constant> trueValue(topAndPopStack(stackOfResults));
		ShPtr<Constant> condition(topAndPopStack(stackOfResults));

		bool condResult(true);
		if (ShPtr<ConstInt> condConstInt = cast<ConstInt>(condition)) {
			condResult = !condConstInt->isZero();
		} else if (ShPtr<ConstFloat> condConstFloat = cast<ConstFloat>(
				condition)) {
			condResult = !condConstFloat->isZero();
		} else if (ShPtr<ConstBool> condConstBool = cast<ConstBool>(condition)) {
			condResult = condConstBool->getValue();
		} else {
			canBeEvaluated = false;
		}

		stackOfResults.push(condResult ? trueValue : falseValue);
	}
}

void ArithmExprEvaluator::visit(ShPtr<CallExpr> expr) {
	canBeEvaluated = false;
}

void ArithmExprEvaluator::visit(ShPtr<BitCastExpr> expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ShPtr<Constant> constant(topAndPopStack(stackOfResults));
		resolveCast(expr, constant);
		stackOfResults.push(constant);
	}
}

void ArithmExprEvaluator::visit(ShPtr<ExtCastExpr> expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ShPtr<Constant> constant(topAndPopStack(stackOfResults));
		resolveCast(expr, constant);
		stackOfResults.push(constant);
	}
}

void ArithmExprEvaluator::visit(ShPtr<TruncCastExpr> expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ShPtr<Constant> constant(topAndPopStack(stackOfResults));
		resolveCast(expr, constant);
		stackOfResults.push(constant);
	}
}

void ArithmExprEvaluator::visit(ShPtr<FPToIntCastExpr> expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ShPtr<Constant> constant(topAndPopStack(stackOfResults));
		resolveCast(expr, constant);
		stackOfResults.push(constant);
	}
}

void ArithmExprEvaluator::visit(ShPtr<IntToFPCastExpr> expr) {
	OrderedAllVisitor::visit(expr);

	if (canBeEvaluated) {
		ShPtr<Constant> constant(topAndPopStack(stackOfResults));
		resolveCast(expr, constant);
		stackOfResults.push(constant);
	}
}

void ArithmExprEvaluator::visit(ShPtr<IntToPtrCastExpr> expr) {
	canBeEvaluated = false;
}

void ArithmExprEvaluator::visit(ShPtr<PtrToIntCastExpr> expr) {
	canBeEvaluated = false;
}

void ArithmExprEvaluator::visit(ShPtr<ConstBool> constant) {
	stackOfResults.push(constant);
}

void ArithmExprEvaluator::visit(ShPtr<ConstFloat> constant) {
	stackOfResults.push(constant);
}

void ArithmExprEvaluator::visit(ShPtr<ConstInt> constant) {
	stackOfResults.push(constant);
}

void ArithmExprEvaluator::visit(ShPtr<ConstSymbol> constant) {
	stackOfResults.push(constant->getValue());
}

void ArithmExprEvaluator::visit(ShPtr<ConstNullPointer> constant) {
	canBeEvaluated = false;
}

void ArithmExprEvaluator::visit(ShPtr<ConstString> constant) {
	canBeEvaluated = false;
}

void ArithmExprEvaluator::visit(ShPtr<ConstArray> constant) {
	canBeEvaluated = false;
}

void ArithmExprEvaluator::visit(ShPtr<ConstStruct> constant) {
	canBeEvaluated = false;
}

void ArithmExprEvaluator::visit(ShPtr<Variable> var) {
	auto it = varValues->find(var);
	if (it != varValues->end()) {
		stackOfResults.push(it->second);
	} else {
		canBeEvaluated = false;
	}
}

void ArithmExprEvaluator::resolveTypesUnaryOp(ShPtr<Constant> &operand) {}

void ArithmExprEvaluator::resolveTypesBinaryOp(ConstPair &constPair) {}

void ArithmExprEvaluator::resolveOpSpecifications(ShPtr<AddOpExpr> expr,
	ConstPair &constPair) {}

void ArithmExprEvaluator::resolveOpSpecifications(ShPtr<AndOpExpr> expr,
	ConstPair &constPair) {}

void ArithmExprEvaluator::resolveOpSpecifications(ShPtr<BitAndOpExpr> expr,
	ConstPair &constPair) {}

void ArithmExprEvaluator::resolveOpSpecifications(ShPtr<BitOrOpExpr> expr,
	ConstPair &constPair) {}

void ArithmExprEvaluator::resolveOpSpecifications(ShPtr<BitShlOpExpr> expr,
	ConstPair &constPair) {}

void ArithmExprEvaluator::resolveOpSpecifications(ShPtr<BitShrOpExpr> expr,
	ConstPair &constPair) {}

void ArithmExprEvaluator::resolveOpSpecifications(ShPtr<BitXorOpExpr> expr,
	ConstPair &constPair) {}

void ArithmExprEvaluator::resolveOpSpecifications(ShPtr<DivOpExpr> expr,
	ConstPair &constPair) {}

void ArithmExprEvaluator::resolveOpSpecifications(ShPtr<EqOpExpr> expr,
	ConstPair &constPair) {}

void ArithmExprEvaluator::resolveOpSpecifications(ShPtr<GtOpExpr> expr,
	ConstPair &constPair) {}

void ArithmExprEvaluator::resolveOpSpecifications(ShPtr<GtEqOpExpr> expr,
	ConstPair &constPair) {}

void ArithmExprEvaluator::resolveOpSpecifications(ShPtr<LtEqOpExpr> expr,
	ConstPair &constPair) {}

void ArithmExprEvaluator::resolveOpSpecifications(ShPtr<LtOpExpr> expr,
	ConstPair &constPair) {}

void ArithmExprEvaluator::resolveOpSpecifications(ShPtr<ModOpExpr> expr,
	ConstPair &constPair) {}

void ArithmExprEvaluator::resolveOpSpecifications(ShPtr<MulOpExpr> expr,
	ConstPair &constPair) {}

void ArithmExprEvaluator::resolveOpSpecifications(ShPtr<NegOpExpr> expr,
	ShPtr<Constant> &constant) {}

void ArithmExprEvaluator::resolveOpSpecifications(ShPtr<NeqOpExpr> expr,
	ConstPair &constPair) {}

void ArithmExprEvaluator::resolveOpSpecifications(ShPtr<NotOpExpr> expr,
	ShPtr<Constant> &constant) {}

void ArithmExprEvaluator::resolveOpSpecifications(ShPtr<OrOpExpr> expr,
	ConstPair &constPair) {}

void ArithmExprEvaluator::resolveOpSpecifications(ShPtr<SubOpExpr> expr,
	ConstPair &constPair) {}

void ArithmExprEvaluator::resolveCast(ShPtr<BitCastExpr> expr,
	ShPtr<Constant> &constant) {}

void ArithmExprEvaluator::resolveCast(ShPtr<ExtCastExpr> expr,
	ShPtr<Constant> &constant) {}

void ArithmExprEvaluator::resolveCast(ShPtr<FPToIntCastExpr> expr,
	ShPtr<Constant> &constant) {}

void ArithmExprEvaluator::resolveCast(ShPtr<IntToFPCastExpr> expr,
	ShPtr<Constant> &constant) {}

void ArithmExprEvaluator::resolveCast(ShPtr<TruncCastExpr> expr,
	ShPtr<Constant> &constant) {}

void ArithmExprEvaluator::resolveOverflowForAPInt(bool overflow) {}

void ArithmExprEvaluator::resolveOverflowForAPFloat(llvm::APFloat::opStatus
	opStatus) {}

/**
* @brief Get operand from @c stackOfResults and call resolve types method that
*        is implemented in sub-evaluators.
*
* @return Constant operand after types corrections.
*/
ShPtr<Constant> ArithmExprEvaluator::getOperandForUnaryOpAndResolveTypes() {
	ShPtr<Constant> operand(topAndPopStack(stackOfResults));
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
* @return A pair of casted constants if the cast was correct, Nothing<>
*         otherwise.
*/
template<typename ConstType>
Maybe<std::pair<ShPtr<ConstType>, ShPtr<ConstType>>> ArithmExprEvaluator::
		castConstPair(const ConstPair &constPair) {
	ShPtr<ConstType> firstConst(cast<ConstType>(constPair.first));
	ShPtr<ConstType> secConst(cast<ConstType>(constPair.second));
	if (!firstConst || !secConst) {
		return Nothing<std::pair<ShPtr<ConstType>, ShPtr<ConstType>>>();
	} else {
		return Just(std::make_pair(firstConst, secConst));
	}
}

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
ShPtr<ConstInt> ArithmExprEvaluator::performOperationOverApInt(
		const Maybe<ConstIntPair> &constIntPair, LLVMAPIntAPIntBoolOp op,
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
ShPtr<ConstInt> ArithmExprEvaluator::performOperationOverApInt(
		const Maybe<ConstIntPair> &constIntPair, LLVMAPIntAPIntOp op) {
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
ShPtr<ConstBool> ArithmExprEvaluator::performOperationOverApInt(
		const Maybe<ConstIntPair> &constIntPair, LLVMBoolAPIntOp op) {
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
		const Maybe<ConstFloatPair> &constFloatPair) {
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
ShPtr<ConstFloat> ArithmExprEvaluator::performOperationOverApFloat(
		const Maybe<ConstFloatPair> &constFloatPair, LLVMAPFloatOp op, llvm::
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
ShPtr<ConstFloat> ArithmExprEvaluator::performOperationOverApFloat(
		const Maybe<ConstFloatPair> &constFloatPair, LLVMAPFloatOpNoRounding op,
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
		const Maybe<ConstIntPair> &constIntPair) {
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
		const Maybe<ConstFloatPair> &constFloatPair) {
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
bool ArithmExprEvaluator::isConstantZero(ShPtr<Constant> constant) {
	ShPtr<ConstInt> secConstInt(cast<ConstInt>(constant));
	ShPtr<ConstFloat> secConstFloat(cast<ConstFloat>(constant));
	return (secConstInt && secConstInt->isZero()) ||
			(secConstFloat && secConstFloat->isZero());
}

} // namespace llvmir2hll
} // namespace retdec

/**
* @file src/llvmir2hll/evaluator/arithm_expr_evaluators/c_arithm_expr_evaluator.cpp
* @brief Implementation of CArithmExprEvaluator.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/evaluator/arithm_expr_evaluator_factory.h"
#include "retdec/llvmir2hll/evaluator/arithm_expr_evaluators/c_arithm_expr_evaluator.h"
#include "retdec/llvmir2hll/ir/binary_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_cast_expr.h"
#include "retdec/llvmir2hll/ir/div_op_expr.h"
#include "retdec/llvmir2hll/ir/ext_cast_expr.h"
#include "retdec/llvmir2hll/ir/float_type.h"
#include "retdec/llvmir2hll/ir/fp_to_int_cast_expr.h"
#include "retdec/llvmir2hll/ir/int_to_fp_cast_expr.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/mod_op_expr.h"
#include "retdec/llvmir2hll/ir/trunc_cast_expr.h"
#include "retdec/llvmir2hll/ir/type.h"
#include "retdec/llvmir2hll/pattern/pattern_finders/api_call/api_call_info.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/types.h"

namespace retdec {
namespace llvmir2hll {

namespace {

/// Default bit width.
const int DEFAULT_INT_BIT_WIDTH = 32;

/**
* @brief Convert bit width of operands to same one. As result bit width is
*        selected the higher one.
*
* @param[in, out] apsIntPair Pair of @c llvm::APSInt.
*/
void convertOperandsToSameBitWidth(ArithmExprEvaluator::APSIntPair &apsIntPair) {
	if (apsIntPair.first.getBitWidth() < apsIntPair.second.getBitWidth()) {
		apsIntPair.first = apsIntPair.first.extend(apsIntPair.second.
			getBitWidth());
	} else if (apsIntPair.first.getBitWidth() > apsIntPair.second.getBitWidth()) {
		apsIntPair.second = apsIntPair.second.extend(apsIntPair.first.
			getBitWidth());
	}
}

/**
* @brief Convert semantics of operands to same one. As result semantics is
*        selected the higher one.
*
* @param[in, out] apFloatPair Par if @c llvm::APFloat.
*/
void convertOperandsToSameSemantics(ArithmExprEvaluator::APFloatPair
		&apFloatPair) {
	bool status;
	unsigned int firstSize = apFloatPair.first.getLargest(apFloatPair.first.
		getSemantics(), true).bitcastToAPInt().getBitWidth();
	unsigned int secondSize = apFloatPair.second.getLargest(apFloatPair.second.
		getSemantics(), true).bitcastToAPInt().getBitWidth();

	if (firstSize < secondSize) {
		apFloatPair.first.convert(apFloatPair.second.getSemantics(),
			llvm::APFloat::rmTowardZero, &status);
	} else if (firstSize > secondSize) {
		apFloatPair.second.convert(apFloatPair.first.getSemantics(),
			llvm::APFloat::rmTowardZero, &status);
	}
}

/**
* @brief Tries to convert the given constant integer to a constant float.
*
* When the constant integer cannot be converted, it returns the null pointer.
*/
ShPtr<ConstFloat> constIntToConstFloat(ShPtr<ConstInt> constInt) {
	llvm::APFloat apFloat(
		constInt->getValue().roundToDouble(constInt->isSigned())
	);
	// On a MSVC build, roundToDouble() returns 0.0 when the bit width of
	// constInt is too big (> 64). If this is the case, the coversion failed,
	// so signal a failure instead of returning an invalid value (0.0).
	if (apFloat.isZero() && !constInt->isZero()) {
		return nullptr;
	}
	return ConstFloat::create(apFloat);
}

/**
* @brief Returns if both operands are signed or both operands are unsigned.
*
* @param[in, out] apsIntPair Pair of @c llvm::APSint.
*
* @return @c true if both operands are signed or both operands are unsigned,
*         otherwise @c false.
*/
bool isSignedOrUnsignedOperands(ArithmExprEvaluator::APSIntPair &apsIntPair) {
	return (apsIntPair.first.isSigned() && apsIntPair.second.isSigned()) ||
		(!apsIntPair.first.isSigned() && !apsIntPair.second.isSigned());
}

/**
* @brief Returns if both operands have same bit width.
*
* @param[in, out] apsIntPair Pair of @c llvm::APSInt.
*
* @return @c true if both of operands have same bit width, otherwise @c false.
*/
bool hasOperandsSameBitWidth(const ArithmExprEvaluator::APSIntPair &apsIntPair) {
	return apsIntPair.first.getBitWidth() == apsIntPair.second.getBitWidth();
}

/**
* @brief Try convert both of operands from @a constPair from @c ConstBool to
*        @c ConstInt.
*
* This is possible only if @a constPair contains operands which are @c ConstBool.
*
* @param[in, out] constPair Pair of constants.
*/
void tryConvertBoolBoolToInt(ArithmExprEvaluator::ConstPair &constPair) {
	if (Maybe<ArithmExprEvaluator::ConstBoolPair> constBoolPair =
			ArithmExprEvaluator::castConstPair<ConstBool>(constPair)) {
		constPair.first = ConstInt::create(constBoolPair->first->getValue(),
			DEFAULT_INT_BIT_WIDTH);
		constPair.second = ConstInt::create(constBoolPair->second->getValue(),
			DEFAULT_INT_BIT_WIDTH);
	}
}

/**
* @brief Try convert operands from @a constPair to @c ConstFloat.
*
* This is possible only if one of operands is a @c ConstFloat, the second is a
* @c ConstInt, and the conversion can be done (some integral values cannot be
* represented as floats).
*
* @param[in, out] constPair Pair of constants.
*/
void tryConvertFloatIntToFloat(ArithmExprEvaluator::ConstPair &constPair) {
	if (isa<ConstFloat>(constPair.first)) {
		if (ShPtr<ConstInt> constInt = cast<ConstInt>(constPair.second)) {
			if (ShPtr<ConstFloat> constFloat = constIntToConstFloat(constInt)) {
				constPair.second = constFloat;
			}
		}
	} else if (isa<ConstFloat>(constPair.second)) {
		if (ShPtr<ConstInt> constInt = cast<ConstInt>(constPair.first)) {
			if (ShPtr<ConstFloat> constFloat = constIntToConstFloat(constInt)) {
				constPair.first = constFloat;
			}
		}
	}
}

/**
* @brief Try convert operands from @a constPair to @c ConstInt.
*
* This is possible only if one of operands is a @c ConstBool and the second is a
* @c ConstInt.
*
* @param[in, out] constPair Pair of constants.
*/
void tryConvertBoolIntToInt(ArithmExprEvaluator::ConstPair &constPair) {
	if (ShPtr<ConstBool> constBool = cast<ConstBool>(constPair.first)) {
		if (isa<ConstInt>(constPair.second)) {
			constPair.first = ConstInt::create(constBool->getValue(),
				DEFAULT_INT_BIT_WIDTH);
		}
	} else if (ShPtr<ConstBool> constBool = cast<ConstBool>(constPair.second)) {
		if (isa<ConstInt>(constPair.first)) {
			constPair.second = ConstInt::create(constBool->getValue(),
				DEFAULT_INT_BIT_WIDTH);
		}
	}
}

} // anonymous namespace

REGISTER_AT_FACTORY("c", C_ARITHM_EXPR_EVALUATOR_ID,
	ArithmExprEvaluatorFactory, CArithmExprEvaluator::create);

/**
* @brief Constructs the CArithmExprEvaluator.
*/
CArithmExprEvaluator::CArithmExprEvaluator() {}

/**
* @brief Destructor.
*/
CArithmExprEvaluator::~CArithmExprEvaluator() {}

/**
* @brief Creates a new CArithmExprEvaluator.
*/
ShPtr<ArithmExprEvaluator> CArithmExprEvaluator::create() {
	return ShPtr<ArithmExprEvaluator>(new CArithmExprEvaluator());
}

std::string CArithmExprEvaluator::getId() const {
	return C_ARITHM_EXPR_EVALUATOR_ID;
}

/**
* @brief Resolve type of operand in unary operation.
*
* @param[in, out] operand Operand on which is resolved types correction.
*/
void CArithmExprEvaluator::resolveTypesUnaryOp(ShPtr<Constant> &operand) {
	if (ShPtr<ConstBool> constBool = cast<ConstBool>(operand)) {
		operand = ConstInt::create(constBool->getValue(), DEFAULT_INT_BIT_WIDTH,
			true);
	}
}

/**
* @brief Resolve types of operands in binary operations.
*
* @param[in, out] constPair Pair of constants on which is resolved types.
*/
void CArithmExprEvaluator::resolveTypesBinaryOp(ConstPair &constPair) {
	tryConvertBoolBoolToInt(constPair);
	if (!constPair.first->getType()->isEqualTo(constPair.second->getType())) {
		// Different types of operands, try to cast to same one.
		tryConvertFloatIntToFloat(constPair);
		tryConvertBoolIntToInt(constPair);
	}

	// Problems with integer bit width and signed/unsigned types.
	if (Maybe<ConstIntPair> constIntPair = castConstPair<ConstInt>(constPair)) {
		APSIntPair apsIntPair(getAPSIntsFromConstants(constIntPair));
		if (isSignedOrUnsignedOperands(apsIntPair) &&
				!hasOperandsSameBitWidth(apsIntPair)) {
			// Different bit width, same signed/unsigned type.
			// Resolution: convert to same bit width. Extend from lower bit
			//             width to the highest bit width of operands.
			convertOperandsToSameBitWidth(apsIntPair);
			constPair.first = ConstInt::create(apsIntPair.first);
			constPair.second = ConstInt::create(apsIntPair.second);
		} else if (!isSignedOrUnsignedOperands(apsIntPair) &&
				hasOperandsSameBitWidth(apsIntPair)) {
			// Same bit width, different signed/unsigned type on operands.
			// Resolution: convert both operands to unsigned.
			if (apsIntPair.first.isSigned() && !apsIntPair.second.isSigned()) {
				constPair.first = ConstInt::create(apsIntPair.first, false);
			} else if (!apsIntPair.first.isSigned() && apsIntPair.second.
					isSigned()) {
				constPair.second = ConstInt::create(apsIntPair.second, false);
			}
		} else if (!isSignedOrUnsignedOperands(apsIntPair) &&
				!hasOperandsSameBitWidth(apsIntPair)) {
			// Different bit width, different signed/unsigned type on operands.
			// Resolution:
			// 1. Convert to same bit width. Extend from lower bit width to the
			//    highest bit width of operands.
			// 2. Convert type (signed/unsigned) from operand with lower bit
			//    width to type of the second operand with higher bit width.
			APSIntPair temp(apsIntPair);
			convertOperandsToSameBitWidth(apsIntPair);
			if (temp.first.getBitWidth() != apsIntPair.first.getBitWidth()) {
				constPair.first = ConstInt::create(apsIntPair.first, apsIntPair.
					second.isSigned());
			} else if (temp.second.getBitWidth() != apsIntPair.second.
					getBitWidth()) {
				constPair.second = ConstInt::create(apsIntPair.second, apsIntPair.
					first.isSigned());
			}
		}
	}

	// Conversion to same float semantics (same size).
	if (Maybe<ConstFloatPair> constFloatPair = castConstPair<ConstFloat>(
			constPair)) {
		APFloatPair apFloatPair = getAPFloatsFromConstants(constFloatPair);
		convertOperandsToSameSemantics(apFloatPair);
		constPair.first = ConstFloat::create(apFloatPair.first);
		constPair.second = ConstFloat::create(apFloatPair.second);
	}
}

void CArithmExprEvaluator::resolveOpSpecifications(ShPtr<DivOpExpr> expr,
		ConstPair &constPair) {
	if (isa<ConstInt>(constPair.second) && isConstantZero(constPair.second)) {
		// Integer division with zero is not defined in C language.
		canBeEvaluated = false;
		return;
	}
}

void CArithmExprEvaluator::resolveOpSpecifications(ShPtr<ModOpExpr> expr,
		ConstPair &constPair) {
	// Remaindering with zero is not defined in C language.
	canBeEvaluated &= !isConstantZero(constPair.second);
}

void CArithmExprEvaluator::resolveCast(ShPtr<BitCastExpr> expr,
		ShPtr<Constant> &constant) {
	if (isa<IntType>(expr->getType())) {
		if (ShPtr<ConstFloat> constFloat = cast<ConstFloat>(expr->getOperand())) {
			constant = ConstInt::create(constFloat->getValue().bitcastToAPInt());
		} else {
			canBeEvaluated = false;
		}
	} else if (ShPtr<FloatType> floatType = cast<FloatType>(expr->getType())) {
		// TODO - implement bitCast from ConstInt or ConstBool to ConstFloat.
		// Now is not implemented because wasn't find function to do this
		// operation.
		canBeEvaluated = false;
	} else {
		canBeEvaluated = false;
	}
}

void CArithmExprEvaluator::resolveCast(ShPtr<ExtCastExpr> expr,
		ShPtr<Constant> &constant) {
	if (ShPtr<IntType> intType = cast<IntType>(expr->getType())) {
		if (ShPtr<ConstInt> constInt = cast<ConstInt>(constant)) {
			if (intType->getSize() <= constInt->getValue().getBitWidth()) {
				// Extension can be only from lower bitWidth to higher.
				canBeEvaluated = false;
				return;
			}
			if (expr->getVariant() == ExtCastExpr::Variant::ZExt) {
				constant = ConstInt::create(
					constInt->getValue().zext(intType->getSize()));
			} else if (expr->getVariant() == ExtCastExpr::Variant::SExt) {
				constant = ConstInt::create(
					constInt->getValue().sext(intType->getSize()));
			} else {
				canBeEvaluated = false;
			}
		} else if (ShPtr<ConstBool> constBool = cast<ConstBool>(constant)) {
			if (intType->getSize() <= 1) {
				// Extension can be only when bitWidth is more then 1 because we
				// want extend boolean constant.
				canBeEvaluated = false;
				return;
			}
			llvm::APInt apInt(1, int(constBool->getValue()), false);
			if (expr->getVariant() == ExtCastExpr::Variant::ZExt) {
				constant = ConstInt::create(apInt.zext(intType->getSize()));
			} else if (expr->getVariant() == ExtCastExpr::Variant::SExt) {
				constant = ConstInt::create(apInt.sext(intType->getSize()));
			} else {
					canBeEvaluated = false;
			}
		} else {
			canBeEvaluated = false;
		}
	} else if (ShPtr<FloatType> floatType = cast<FloatType>(expr->getType())) {
		// TODO: Add support for FloatType. Can't find llvm function to
		// extend float. Probably need to save semantics in FloatType.
		canBeEvaluated = false;
	} else {
		canBeEvaluated = false;
	}
}

void CArithmExprEvaluator::resolveCast(ShPtr<FPToIntCastExpr> expr,
		ShPtr<Constant> &constant) {
	if (ShPtr<ConstFloat> constFloat = cast<ConstFloat>(constant)) {
		if (ShPtr<IntType> intType = cast<IntType>(expr->getType())) {
			// NAN and INFINITY not supported conversion to Int in IEEE-754.
			if (constFloat->getValue().isInfinity() || constFloat->getValue().
				isNaN()) {
				canBeEvaluated = false;
				return;
			}
			llvm::APSInt apsInt(intType->getSize(), 0);
			bool status;
			constFloat->getValue().convertToInteger(apsInt, llvm::APFloat::
				rmTowardZero, &status);
			constant = ConstInt::create(apsInt);
		} else {
			canBeEvaluated = false;
		}
	} else {
		canBeEvaluated = false;
	}
}

void CArithmExprEvaluator::resolveCast(ShPtr<IntToFPCastExpr> expr,
		ShPtr<Constant> &constant) {
	if (isa<FloatType>(expr->getType())) {
		ShPtr<ConstInt> constInt = cast<ConstInt>(constant);
		ShPtr<ConstBool> constBool = cast<ConstBool>(constant);
		if ((!constInt && !constBool)) {
			canBeEvaluated = false;
			return;
		}
		llvm::APFloat apFloat(0.0);
		if (constInt) {
			apFloat.convertFromAPInt(constInt->getValue(), constInt->isSigned(),
				llvm::APFloat::rmTowardZero);
		} else if (constBool) {
			llvm::APInt apInt(1, int(constBool->getValue()), false);
			apFloat.convertFromAPInt(apInt, false, llvm::APFloat::rmTowardZero);
		}
		constant = ConstFloat::create(apFloat);
	} else {
		canBeEvaluated = false;
	}
}

void CArithmExprEvaluator::resolveCast(ShPtr<TruncCastExpr> expr,
		ShPtr<Constant> &constant) {
	if (ShPtr<IntType> intType = cast<IntType>(expr->getType())) {
		if (ShPtr<ConstInt> constInt = cast<ConstInt>(constant)) {
			if (intType->getSize() >= constInt->getValue().getBitWidth()) {
				// Truncate can be only from higher bitWidth to lower.
				canBeEvaluated = false;
				return;
			}
			constant = ConstInt::create(
				constInt->getValue().trunc(intType->getSize()));
		} else {
			// Truncate is not supported on ConstBool and ConstFloat when
			// we want truncate to IntType.
			canBeEvaluated = false;
		}
	} else if (ShPtr<FloatType> floatType = cast<FloatType>(expr->getType())) {
		// TODO: Add support for FloatType. Can't find llvm function to
		// extend float. Probably need to save semantics in FloatType.
		canBeEvaluated = false;
	} else {
		canBeEvaluated = false;
	}
}

/**
* @brief Resolve overflow specifications for float and double.
*
* @param[in] opStatus Status to check.
*/
void CArithmExprEvaluator::resolveOverflowForAPFloat(
		llvm::APFloat::opStatus opStatus) {
	if (opStatus == llvm::APFloat::opInvalidOp) {
		canBeEvaluated = false;
	}
}

} // namespace llvmir2hll
} // namespace retdec

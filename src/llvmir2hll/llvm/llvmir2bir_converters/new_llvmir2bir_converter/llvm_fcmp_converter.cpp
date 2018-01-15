/**
* @file src/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/llvm_fcmp_converter.cpp
* @brief Implementation of LLVMFCmpConverter.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instructions.h>

#include "retdec/llvmir2hll/ir/and_op_expr.h"
#include "retdec/llvmir2hll/ir/const_bool.h"
#include "retdec/llvmir2hll/ir/eq_op_expr.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/gt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/gt_op_expr.h"
#include "retdec/llvmir2hll/ir/lt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/lt_op_expr.h"
#include "retdec/llvmir2hll/ir/neq_op_expr.h"
#include "retdec/llvmir2hll/ir/or_op_expr.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/llvm_fcmp_converter.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new fcmp converter.
*/
LLVMFCmpConverter::LLVMFCmpConverter():
	optionStrictFPUSemantics(false) {}

/**
* @brief Converts the given LLVM fcmp instruction @a inst into an expression
*        in BIR.
*
* @param[in] op1 Already converted first operand as expression in BIR.
* @param[in] op2 Already converted second operand as expression in BIR.
* @param[in] predicate Given fcmp predicate.
*/
ShPtr<Expression> LLVMFCmpConverter::convertToExpression(ShPtr<Expression> op1,
		ShPtr<Expression> op2, unsigned predicate) {
	switch (predicate) {
		case llvm::CmpInst::FCMP_FALSE:
			// always yields false, regardless of operands
			return ConstBool::create(false);

		case llvm::CmpInst::Predicate::FCMP_OEQ:
			// yields true if both operands are not a QNAN and op1
			// is equal to op2
			return getOrdFCmpExpr<EqOpExpr>(op1, op2);

		case llvm::CmpInst::Predicate::FCMP_OGT:
			// yields true if both operands are not a QNAN and op1
			// is greater than op2
			return getOrdFCmpExpr<GtOpExpr>(op1, op2);

		case llvm::CmpInst::Predicate::FCMP_OGE:
			// yields true if both operands are not a QNAN and op1
			// is greater than or equal to op2
			return getOrdFCmpExpr<GtEqOpExpr>(op1, op2);

		case llvm::CmpInst::Predicate::FCMP_OLT:
			// yields true if both operands are not a QNAN and op1
			// is less than op2
			return getOrdFCmpExpr<LtOpExpr>(op1, op2);

		case llvm::CmpInst::Predicate::FCMP_OLE:
			// yields true if both operands are not a QNAN and op1
			// is less than or equal to op2
			return getOrdFCmpExpr<LtEqOpExpr>(op1, op2);

		case llvm::CmpInst::Predicate::FCMP_ONE:
			// yields true if both operands are not a QNAN and op1
			// is not equal to op2
			return getOrdFCmpExpr<NeqOpExpr>(op1, op2);

		case llvm::CmpInst::Predicate::FCMP_ORD:
			// yields true if both operands are not a QNAN
			return AndOpExpr::create(getExprIsNotQNAN(op1),
				getExprIsNotQNAN(op2));

		case llvm::CmpInst::Predicate::FCMP_UEQ:
			// yields true if either operand is a QNAN or op1 is
			// equal to op2
			return getUnordFCmpExpr<EqOpExpr>(op1, op2);

		case llvm::CmpInst::Predicate::FCMP_UGT:
			// yields true if either operand is a QNAN or op1 is
			// greater than op2
			return getUnordFCmpExpr<GtOpExpr>(op1, op2);

		case llvm::CmpInst::Predicate::FCMP_UGE:
			// yields true if either operand is a QNAN or op1 is
			// greater than or equal to op2
			return getUnordFCmpExpr<GtEqOpExpr>(op1, op2);

		case llvm::CmpInst::Predicate::FCMP_ULT:
			// yields true if either operand is a QNAN or op1 is
			// less than op2
			return getUnordFCmpExpr<LtOpExpr>(op1, op2);

		case llvm::CmpInst::Predicate::FCMP_ULE:
			// yields true if either operand is a QNAN or op1 is
			// less than or equal to op2
			return getUnordFCmpExpr<LtEqOpExpr>(op1, op2);

		case llvm::CmpInst::Predicate::FCMP_UNE:
			// yields true if either operand is a QNAN or op1 is not
			// equal to op2
			return getUnordFCmpExpr<NeqOpExpr>(op1, op2);

		case llvm::CmpInst::Predicate::FCMP_UNO:
			// yields true if either operand is a QNAN
			return OrOpExpr::create(getExprIsQNAN(op1),
				getExprIsQNAN(op2));

		case llvm::CmpInst::Predicate::FCMP_TRUE:
			// always yields true, regardless of operands
			return ConstBool::create(true);

		default:
			// FAIL() is in LLVMInstructionConverter::convertFCmpInstToExpression()
			return nullptr;
	}

	return nullptr;
}

/**
* @brief Enables/disables the use of strict FPU semantics.
*
* @param[in] strict If @c true, enables the use of strict FPU semantics. If @c
*                   false, disables the use of strict FPU semantics.
*/
void LLVMFCmpConverter::setOptionStrictFPUSemantics(bool strict) {
	optionStrictFPUSemantics = strict;
}

/**
* @brief Returns expression which determines if given Expression @a op is a QNAN.
*/
ShPtr<Expression> LLVMFCmpConverter::getExprIsQNAN(ShPtr<Expression> op) const {
	return NeqOpExpr::create(op, op);
}

/**
* @brief Returns expression which determines if given Expression @a op is not
*        a QNAN.
*/
ShPtr<Expression> LLVMFCmpConverter::getExprIsNotQNAN(ShPtr<Expression> op) const {
	return EqOpExpr::create(op, op);
}

/**
* @brief Returns logical expression which represents a comparison of two float
*        operands @a op1 and @a op2, when both operands are not a QNAN.
*
* @tparam T Class that represents a comparison operator in BIR.
*/
template<class T>
ShPtr<Expression> LLVMFCmpConverter::getOrdFCmpExpr(ShPtr<Expression> op1,
		ShPtr<Expression> op2) const {
	return T::create(op1, op2);
}

/**
* @brief Returns logical expression which represents a comparison of two float
*        operands @a op1 and @a op2, when either operand can be a QNAN.
*
* @tparam T Class that represents a comparison operator in BIR.
*/
template<class T>
ShPtr<Expression> LLVMFCmpConverter::getUnordFCmpExpr(ShPtr<Expression> op1,
		ShPtr<Expression> op2) const {
	if (!optionStrictFPUSemantics) {
		return getOrdFCmpExpr<T>(op1, op2);
	}

	auto isAnyOpQNAN = OrOpExpr::create(getExprIsQNAN(op1), getExprIsQNAN(op2));
	return OrOpExpr::create(T::create(op1, op2), isAnyOpQNAN);
}

} // namespace llvmir2hll
} // namespace retdec

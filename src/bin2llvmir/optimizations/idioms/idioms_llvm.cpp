/**
 * @file src/bin2llvmir/optimizations/idioms/idioms_llvm.cpp
 * @brief clang/LLVM instruction idioms
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <llvm/IR/PatternMatch.h>

#include "retdec/bin2llvmir/optimizations/idioms/idioms_llvm.h"

using namespace llvm;
using namespace PatternMatch;

namespace retdec {
namespace bin2llvmir {

/**
 * Exchange (X & SignBit) == 0 with X > -1
 *
 * @param iter value to visit
 * @return replaced Instruction, otherwise nullptr
 */
Instruction * IdiomsLLVM::exchangeIsGreaterThanMinusOne(BasicBlock::iterator iter) const {
	Instruction & val = (*iter);
	Value * op_and = nullptr;
	Value * op_x = nullptr;
	ICmpInst::Predicate pred;
	ConstantInt * cnst = nullptr;

	// (X & SignBit) == 0 --> X > -1
	if (! match(&val, m_ICmp(pred, m_Value(op_and), m_ConstantInt(cnst)))
			&& ! match(&val, m_ICmp(pred, m_ConstantInt(cnst), m_Value(op_and))))
		return nullptr;

	if (pred != ICmpInst::ICMP_EQ || *cnst->getValue().getRawData() != 0)
		return nullptr;

	if (! match(op_and, m_And(m_Value(op_x), m_ConstantInt(cnst)))
			&& ! match(op_and, m_And(m_ConstantInt(cnst), m_Value(op_x))))
		return nullptr;

	if (*cnst->getValue().getRawData() != 0x80000000)
		return nullptr;

	eraseInstFromBasicBlock(op_and, val.getParent());

	Constant *NewCst = ConstantInt::get(op_x->getType(), -1);
	return CmpInst::Create(Instruction::ICmp, ICmpInst::ICMP_SGT, op_x, NewCst);
}

/**
 * Exchange ~(A^B) with icmp eq i1 A, B
 *
 * @param iter value to visit
 * @return replaced Instruction, otherwise nullptr
 */
Instruction * IdiomsLLVM::exchangeCompareEq(BasicBlock::iterator iter) const {
	Instruction & val = *iter;
	Value * op_a;
	Value * op_b;
	Value * op_xor;

	// This idiom is applicable only if i1 is used!
	if (! val.getType()->isIntegerTy(1))
		return nullptr;

	// ~(A^B) --> icmp eq i1 A, B
	if (! BinaryOperator::isNot(&val))
		return nullptr;

	op_xor = val.getOperand(0);

	if (! match(op_xor, m_Xor(m_Value(op_a), m_Value(op_b))))
		return nullptr;

	eraseInstFromBasicBlock(op_xor, val.getParent());

	return CmpInst::Create(Instruction::ICmp, ICmpInst::ICMP_EQ, op_a, op_b);
}

/**
 * Exchange A^B with icmp eq i1 A, B
 *
 * @param iter value to visit
 * @return replaced Instruction, otherwise nullptr
 */
Instruction * IdiomsLLVM::exchangeCompareNeq(BasicBlock::iterator iter) const {
	Instruction & val = *iter;
	Value * op_a;
	Value * op_b;

	// This idiom is applicable only if i1 is used!
	if (! val.getType()->isIntegerTy(1))
		return nullptr;

	// A^B --> icmp eq i1 A, B
	if (! match(&val, m_Xor(m_Value(op_a), m_Value(op_b))))
		return nullptr;

	return CmpInst::Create(Instruction::ICmp, ICmpInst::ICMP_NE, op_a, op_b);
}

/**
 * Exchange ~A & B with icmp slt i1 A, B
 *
 * @param iter value to visit
 * @return replaced Instruction, otherwise nullptr
 */
Instruction * IdiomsLLVM::exchangeCompareSlt(BasicBlock::iterator iter) const {
	Instruction & val = *iter;
	Value * op0;
	Value * op1;
	Value * op_a;
	Value * op_b;
	Value * op_not;

	// This idiom is applicable only if i1 is used!
	if (! val.getType()->isIntegerTy(1))
		return nullptr;

	// ~A & B --> icmp ult i1 A, B
	if (! match(&val, m_And(m_Value(op0), m_Value(op1))))
		return nullptr;

	if (! match(op0, m_Not(m_Value(op_a)))) {
		op_b = op0;
		op_not = op1;

		if (! match(op1, m_Not(m_Value(op_a))))
			return nullptr;
	} else {
		op_not = op0;
		op_b = op1;
	}

	eraseInstFromBasicBlock(op_not, val.getParent());

	return CmpInst::Create(Instruction::ICmp, ICmpInst::ICMP_SLT, op_a, op_b);
}

/**
 * Exchange ~A | B with icmp sle i1 A, B
 *
 * @param iter value to visit
 * @return replaced Instruction, otherwise nullptr
 */
Instruction * IdiomsLLVM::exchangeCompareSle(BasicBlock::iterator iter) const {
	Instruction & val = *iter;
	Value * op0;
	Value * op1;
	Value * op_a;
	Value * op_b;
	Value * op_not;

	// This idiom is applicable only if i1 is used!
	if (! val.getType()->isIntegerTy(1))
		return nullptr;

	// ~A | B --> icmp ule i1 A, B
	if (! match(&val, m_Or(m_Value(op0), m_Value(op1))))
		return nullptr;

	if (! match(op0, m_Not(m_Value(op_a)))) {
		op_not = op1;
		op_b = op0;

		if (! match(op1, m_Not(m_Value(op_a))))
			return nullptr;
	} else {
		op_not = op0;
		op_b = op1;
	}

	eraseInstFromBasicBlock(op_not, val.getParent());

	return CmpInst::Create(Instruction::ICmp, ICmpInst::ICMP_SLE, op_a, op_b);
}

} // namespace bin2llvmir
} // namespace retdec

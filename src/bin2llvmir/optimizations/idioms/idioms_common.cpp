/**
 * @file src/bin2llvmir/optimizations/idioms/idioms_common.cpp
 * @brief Common compiler instruction idioms
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <cmath>

#include <llvm/IR/PatternMatch.h>

#include "retdec/bin2llvmir/optimizations/idioms/idioms_common.h"

using namespace llvm;
using namespace PatternMatch;

namespace retdec {
namespace bin2llvmir {

/**
 * Exchange shift left with a division
 *
 * @param iter value to visit
 * @return replaced Instruction, otherwise nullptr
 */
Instruction * IdiomsCommon::exchangeBitShiftUDiv(BasicBlock::iterator iter) const {
	Instruction & val = (*iter);
	Value * op0 = nullptr;
	ConstantInt * cnst = nullptr;

	// X u>> C --> X / 2^C
	if (match(&val, m_LShr(m_Value(op0), m_ConstantInt(cnst))) &&
			isPowerOfTwoRepresentable(cnst)) {
		Constant *NewCst = ConstantInt::get(cnst->getType(),
						pow(2, *cnst->getValue().getRawData()));
		BinaryOperator *div = BinaryOperator::CreateUDiv(op0, NewCst);
		return div;
	}

	return nullptr;
}

/**
 * Exchange x u>> 31 with x < 0
 *
 * @param iter value to visit
 * @return replaced Instruction, otherwise nullptr
 */
Instruction * IdiomsCommon::exchangeLessThanZero(BasicBlock::iterator iter) const {
	Instruction & val = (*iter);
	Value * op0 = nullptr;
	ConstantInt * cnst = nullptr;

	// X u>> 31 --> X < 0
	if (match(&val, m_LShr(m_Value(op0), m_ConstantInt(cnst)))
				&& *cnst->getValue().getRawData() == 31) {
		Constant *NewCst = ConstantInt::get(op0->getType(), 0);

		Instruction * cmp = CmpInst::Create(Instruction::ICmp, ICmpInst::ICMP_SLT, op0, NewCst);
		val.getParent()->getInstList().insert(iter, cmp);

		return CastInst::CreateZExtOrBitCast(cmp, val.getType());
	}

	return nullptr;
}

/**
 * Exchange:
 *   ((X u>> 31) ^ 1)  --> X >= 0
 *   ((X ^ -1) u>> 31) --> X >= 0
 *
 * @param iter value to visit
 * @return replaced Instruction, otherwise nullptr
 */
Instruction * IdiomsCommon::exchangeGreaterEqualZero(BasicBlock::iterator iter) const {
	Instruction & val = (*iter);
	Value * op0 = nullptr;
	Value * op1 = nullptr;
	ConstantInt * cnst = nullptr;

	// ((X u>> 31) ^ 1) --> X >= 0
	//
	if ((match(&val, m_Xor(m_Value(op0), m_ConstantInt(cnst)))
			|| match(&val, m_Xor(m_ConstantInt(cnst), m_Value(op0))))
				&& cnst->isOne()) {

		if (match(op0, m_LShr(m_Value(op1), m_ConstantInt(cnst)))
				&& *cnst->getValue().getRawData() == 31) {

			Constant *NewCst = ConstantInt::get(op0->getType(), 0);

			Instruction * cmp = CmpInst::Create(Instruction::ICmp, ICmpInst::ICMP_SGE, op1, NewCst);
			val.getParent()->getInstList().insert(iter, cmp);

			// erase lshr
			eraseInstFromBasicBlock(op0, val.getParent());

			return CastInst::CreateZExtOrBitCast(cmp, val.getType());
		}
	}
	// ((X ^ -1) u>> 31) --> X >= 0
	//
	else if (match(&val, m_LShr(m_Value(op0), m_ConstantInt(cnst)))
				&& *cnst->getValue().getRawData() == 31
				&& (match(op0, m_Xor(m_Value(op1), m_ConstantInt(cnst)))
					|| match(op0, m_Xor(m_ConstantInt(cnst), m_Value(op1))))
				&& cnst->isMinusOne()) {

		Constant *NewCst = ConstantInt::get(op1->getType(), 0);

		Instruction * cmp = CmpInst::Create(Instruction::ICmp, ICmpInst::ICMP_SGE, op1, NewCst);
		val.getParent()->getInstList().insert(iter, cmp);

		return CastInst::CreateZExtOrBitCast(cmp, val.getType());
	}

	return nullptr;
}

/**
 * Exchange shift right with a division.
 * ((X >> 31) & mask) | (X >> shift)
 *
 * @param iter value to visit
 * @return replaced Instruction, otherwise nullptr
 */
Instruction * IdiomsCommon::exchangeBitShiftSDiv1(BasicBlock::iterator iter) const {
	Instruction & val = (*iter);
	Value * op_var1 = nullptr;
	Value * op_var2 = nullptr;
	Value * op_or = nullptr;
	Value * op_and = nullptr;
	Value * op_lshr = nullptr;
	Value * op_ashr = nullptr;
	ConstantInt * cnst = nullptr;

	// TODO: Matula:
	// Very ugly pattern - the problem is that or is comutative -> same pattern
	// twice with switched ops. Try to find out how LLVM is dealing with this,
	// this is probable not a problem unique to decompiler and there may be a
	// better solution for this case, and probably all the other patterns.
	// The original solution is commented out below.
	//
	if (!(match(&val, m_Or(m_Value(op_and), m_Value(op_lshr)))
			&& match(op_and, m_And(m_Value(op_ashr), m_ConstantInt(cnst)))
			&& match(op_ashr, m_AShr(m_Value(op_var1), m_ConstantInt(cnst)))
			&& *cnst->getValue().getRawData() == 31
			&& match(op_lshr, m_LShr(m_Value(op_var2), m_ConstantInt(cnst)))
			&& isPowerOfTwoRepresentable(cnst))
		&&
		!(match(&val, m_Or(m_Value(op_lshr), m_Value(op_and)))
			&& match(op_and, m_And(m_Value(op_ashr), m_ConstantInt(cnst)))
			&& cnst->getValue().getSExtValue() == -2147483648
			&& match(op_ashr, m_AShr(m_Value(op_var1), m_ConstantInt(cnst)))
			&& *cnst->getValue().getRawData() == 31
			&& match(op_lshr, m_LShr(m_Value(op_var2), m_ConstantInt(cnst)))
			&& isPowerOfTwoRepresentable(cnst))
			)
	{
		return nullptr;
	}
	// Original code.
	//
//	if (! match(&val, m_Or(m_Value(op_and), m_Value(op_lshr))))
//		return nullptr;
//
//	if (! match(op_and, m_And(m_Value(op_ashr), m_ConstantInt(cnst))))
//		return nullptr;
//
//	if (! match(op_ashr, m_AShr(m_Value(op_var1), m_ConstantInt(cnst)))
//			|| *cnst->getValue().getRawData() != 31)
//		return nullptr;
//
//	if (! match(op_lshr, m_LShr(m_Value(op_var2), m_ConstantInt(cnst))))
//		return nullptr;
//
//	if (! isPowerOfTwoRepresentable(cnst))
//		return nullptr;

	// now exchange the idiom
	unsigned shift = *cnst->getValue().getRawData();
	Constant *NewCst = ConstantInt::get(val.getType(), pow(2, shift));
	Instruction *res = BinaryOperator::CreateSDiv(op_var1, NewCst);

	eraseInstFromBasicBlock(op_ashr, val.getParent());
	eraseInstFromBasicBlock(op_and, val.getParent());
	eraseInstFromBasicBlock(op_lshr, val.getParent());
	eraseInstFromBasicBlock(op_or, val.getParent());

	return res;
}

/**
 * Exchange shift right with a division.
 *
 * @param iter value to visit
 * @return replaced Instruction, otherwise nullptr
 */
Instruction * IdiomsCommon::exchangeBitShiftSDiv2(BasicBlock::iterator iter) const {
	Instruction & val = (*iter);
	Value * op0 = nullptr;
	ConstantInt * cnst = nullptr;

	// X s>> C --> X / 2^C
	if (match(&val, m_AShr(m_Value(op0), m_ConstantInt(cnst))) &&
			isPowerOfTwoRepresentable(cnst)) {
		Constant *NewCst = ConstantInt::get(cnst->getType(),
						pow(2, *cnst->getValue().getRawData()));
		BinaryOperator *div = BinaryOperator::CreateSDiv(op0, NewCst);
		return div;
	}

	return nullptr;
}

/**
 * Exchange shift left by with a multiplication
 *
 * @param iter value to visit
 * @return replaced Instruction, otherwise nullptr
 */
Instruction * IdiomsCommon::exchangeBitShiftMul(BasicBlock::iterator iter) const {
	Instruction & val = (*iter);
	Value * op0 = nullptr;
	ConstantInt * cnst = nullptr;

	// X << C --> X * 2^C
	if (match(&val, m_Shl(m_Value(op0), m_ConstantInt(cnst))) &&
			isPowerOfTwoRepresentable(cnst)) {
		Constant *NewCst = ConstantInt::get(cnst->getType(),
						pow(2, *cnst->getValue().getRawData()));
		BinaryOperator *mul = BinaryOperator::CreateMul(op0, NewCst);
		return mul;
	}

	return nullptr;
}

/**
 * Exchange x & (k - 1) with x % k
 *
 * @param iter value to visit
 * @return replaced Instruction, otherwise nullptr
 */
Instruction * IdiomsCommon::exchangeUnsignedModulo2n(BasicBlock::iterator iter) const {
	Instruction & val = (*iter);
	Value * op0 = nullptr;
	ConstantInt *cnst = nullptr;

	// X & (k - 1) --> X % k iff k is power of 2
	if (match(&val, m_And(m_Value(op0), m_ConstantInt(cnst)))
			&& isPowerOfTwo(*cnst->getValue().getRawData() + 1)) {
		Constant *NewCst = ConstantInt::get(op0->getType(), cnst->getValue() + 1);
		return BinaryOperator::CreateURem(op0, NewCst);
	}

	return nullptr;
}

/**
 * Exchange -(((lshr(x, 31) + x) >> 1)) with -(x / 2)
 *
 * @param iter value to visit
 * @return replaced Instruction, otherwise nullptr
 */
Instruction * IdiomsCommon::exchangeDivByMinusTwo(BasicBlock::iterator iter) const {
	Instruction & val = (*iter);
	Value * op_add = nullptr;
	Value * op_ashr = nullptr;
	Value * op_add_op1 = nullptr;
	Value * op_add_op2 = nullptr;
	Value * op_x = nullptr;
	ConstantInt * cnst = nullptr;

	// 0 - (((X u>> 31) + X) s>> 1)) -- x / -2
	if (match(&val, m_Sub(m_ConstantInt(cnst), m_Value(op_ashr)))
			&& *cnst->getValue().getRawData() == 0) {

		if (match(op_ashr, m_AShr(m_Value(op_add), m_ConstantInt(cnst)))
				&& *cnst->getValue().getRawData() == 1) {

			if (match(op_add, m_Add(m_Value(op_add_op1), m_Value(op_add_op2)))) {

				if (match(op_add_op1, m_LShr(m_Value(op_x), m_ConstantInt(cnst)))
					|| match(op_add_op2, m_LShr(m_Value(op_x), m_ConstantInt(cnst)))) {
					/*
					 * Previous add is a commutative operation, there can be:
					 *  lshr + X
					 *    or:
					 *  X + lshr
					 * X from lshr can be used, because we know that it is a first use
					 */
					if (op_x == op_add_op1 || op_x == op_add_op2) {
						Constant *NewCst = ConstantInt::get(op_x->getType(), -2);
						Instruction * ret = BinaryOperator::CreateSDiv(op_x, NewCst);

						eraseInstFromBasicBlock(op_add, val.getParent());
						eraseInstFromBasicBlock(op_ashr, val.getParent());

						// which one is lshr? erase it!
						if (op_x == op_add_op1)
							eraseInstFromBasicBlock(op_add_op2, val.getParent());
						else
							eraseInstFromBasicBlock(op_add_op1, val.getParent());

						return ret;
					}
				}
			}
		}
	}

	return nullptr;
}

/*
 * Exchange (((lshr(lshr(X, 31), 27) + X) & N) - lshr((X >> 31), K)) with X % (N + 1)
 *
 * @param iter value to visit
 * @return replaced Instruction, otherwise nullptr
 */
Instruction * IdiomsCommon::exchangeSignedModulo2n(BasicBlock::iterator iter) const {
	Instruction & val = (*iter);
	Value * op_add = nullptr;
	Value * op_and = nullptr;
	Value * op_ashr = nullptr;
	Value * op_ashr1 = nullptr;
	Value * op_lshr = nullptr;
	Value * op_lshr1 = nullptr;
	Value * op_x = nullptr;
	Value * op_x_tmp = nullptr;
	ConstantInt * op_n = nullptr;
	ConstantInt * cnst = nullptr;

	// (((lshr(lshr(X, 31), 27) + X) & N) - lshr((X s>> 31), K)) --> X % (N + 1)
	if (! match(&val, m_Sub(m_Value(op_and), m_Value(op_lshr))))
		return nullptr;

	if (! match(op_lshr, m_LShr(m_Value(op_ashr), m_ConstantInt(cnst))))
		return nullptr;

	if (! match(op_ashr, m_AShr(m_Value(op_x), m_ConstantInt(cnst)))
			|| *cnst->getValue().getRawData() != 31) {
		return nullptr;
	}

	// left hand side of sub
	if (! match(op_and, m_And(m_Value(op_add), m_ConstantInt(op_n)))
			&& ! match(op_and, m_And(m_ConstantInt(op_n), m_Value(op_lshr1))))
		return nullptr;

	if (! match(op_add, m_Add(m_Value(op_lshr1), m_Value(op_x_tmp))))
		return nullptr;

	// are we still using X?
	if (op_x_tmp != op_x) {
		if (op_lshr1 == op_x)
			// we have checked for X, X can be discarded
			op_lshr1 = op_x_tmp;
	}

	if (! match(op_lshr1, m_LShr(m_Value(op_ashr1), m_ConstantInt(cnst))))
		return nullptr;

	if (! match(op_ashr1, m_AShr(m_Value(op_x_tmp), m_ConstantInt(cnst)))
			&& *cnst->getValue().getRawData() != 31)
		return nullptr;

	if (op_x_tmp != op_x)
		return nullptr;

	// now exchange the idiom
	eraseInstFromBasicBlock(op_and, val.getParent());
	eraseInstFromBasicBlock(op_ashr, val.getParent());
	eraseInstFromBasicBlock(op_add, val.getParent());
	eraseInstFromBasicBlock(op_lshr, val.getParent());
	eraseInstFromBasicBlock(op_lshr1, val.getParent());
	eraseInstFromBasicBlock(op_ashr1, val.getParent());

	Constant *NewCst = ConstantInt::get(op_x->getType(), *op_n->getValue().getRawData() + 1);
	return BinaryOperator::CreateSRem(op_x, NewCst);
}

} // namespace bin2llvmir
} // namespace retdec

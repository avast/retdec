/**
 * @file src/bin2llvmir/optimizations/idioms/idioms_magicdivmod.cpp
 * @brief Magic div and modulo exchangers
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>

#include <llvm/IR/PatternMatch.h>

#include "retdec/bin2llvmir/optimizations/idioms/idioms_magicdivmod.h"

using namespace llvm;
using namespace PatternMatch;

namespace retdec {
namespace bin2llvmir {

/**
 * Calculate original divisor from `magic number multiplication' form.
 *
 * @param magic_number a magic number used when multiply
 * @param sh_pre a shift before multiplication
 * @param sh_post a shift after multiplication
 * @return computed divisor
 */
unsigned IdiomsMagicDivMod::divisorByMagicNumberUnsigned(unsigned magic_number, unsigned sh_pre,
														unsigned sh_post)
{
	/*
	 * The simplest (and possibly the fastest) way how to compute original
	 * divisor is simply interpret the division. The dividend is chosen to be
	 * the highest possible unsigned to cover all constants and not to loose
	 * precision.
	 *
	 * Let x be a dividend, k is the original divisor and q is a quotient:
	 * x / k = q
	 * x / q = k
	 *
	 * The original approach that used 32-bit dividend is not enough. Not even
	 * 64-bit is enough for 64-bit idioms. Therefore, we use LLVM APInt with
	 * bitwidth 96-bit for dividend and 128-bit for internal storage of
	 * results.
	 *
	 */

	llvm::APInt x, y, q, r;
	// Set n to 0xFFFFFFFF FFFFFFFF FFFFFFFF (i.e. 96 bits)
	x = x.getAllOnesValue(96).zext(128);
	y = (x * llvm::APInt(128, magic_number)).lshr(32);
	q = ((x - y).lshr(sh_pre) + y).lshr(sh_post);

	if (q == 0)
		return 0;

	llvm::APInt::udivrem(x, q, q, r);
	uint32_t result = q.getLimitedValue(std::numeric_limits<uint32_t>::max());
	return r == 0 ? result : ++result /* ceil */;
}

/**
 * Calculate original divisor from `magic number multiplication' form.
 *
 * @param magic_number a magic number used when multiply
 * @param sh_post a shift after multiplication
 * @return computed divisor
 */
unsigned IdiomsMagicDivMod::divisorByMagicNumberUnsigned2(unsigned magic_number, unsigned sh_post)
{
	/*
	 * The simplest (and possibly the fastest) way how to compute original
	 * divisor is simply interpret the division. The dividend is chosen to be
	 * the highest possible unsigned to cover all constants and not to loose
	 * precision.
	 *
	 * Let x be a dividend, k is the original divisor and q is a quotient:
	 * x / k = q
	 * x / q = k
	 *
	 * The original approach that used 32-bit dividend is not enough. Not even
	 * 64-bit is enough for 64-bit idioms. Therefore, we use LLVM APInt with
	 * bitwidth 96-bit for dividend and 128-bit for internal storage of
	 * results.
	 *
	 */

	llvm::APInt x, q, r;
	// Set n to 0xFFFFFFFF FFFFFFFF FFFFFFFF (i.e. 96 bits)
	x = x.getAllOnesValue(96).zext(128);
	q = (x * llvm::APInt(128, magic_number)).lshr(sh_post);

	if (q == 0)
		return 0;

	llvm::APInt::udivrem(x, q, q, r);
	uint32_t result = q.getLimitedValue(std::numeric_limits<uint32_t>::max());
	return r == 0 ? result : ++result /* ceil */;
}

/**
 * Calculate original divisor from `signed magic number multiplication' form.
 *
 * @param magic_number a magic number used when multiply
 * @param sh_post a shift after multiplication
 * @return computed divisor
 */
int IdiomsMagicDivMod::divisorByMagicNumberSigned(int magic_number, unsigned sh_post)
{
	// TODO: rewrite by using LLVM APInt
	const int32_t n = std::numeric_limits<int32_t>::max(); // No sign bit, quotient is not corrected.
	int32_t q;

	q = ((static_cast<uint64_t>(magic_number) * n) >> 32) >> sh_post; // arithmetical shift!

	return q == 0 ? q : n / q;
}

/**
 * Calculate original divisor from `signed magic number multiplication' form.
 *
 * @param magic_number a magic number used when multiply
 * @param sh_post a shift after multiplication
 * @return computed divisor
 */
int IdiomsMagicDivMod::divisorByMagicNumberSigned2(int magic_number, unsigned sh_post)
{
	// TODO: rewrite by using LLVM APInt
	const int n = std::numeric_limits<int32_t>::max(); // No sign bit, quotient is not corrected.
	int32_t q;

	q = (n + ((static_cast<uint64_t>(magic_number) * n) >> 32)) >> sh_post; // arithmetical shift!

	return q == 0 ? q : n / q;
}

/**
 * Calculate original divisor from `signed magic number multiplication' form.
 * ( value * magic ) >> ( shift )
 *
 * @param magic_number a magic number used when multiply
 * @param shift a shift after multiplication
 * @return computed divisor
 */
unsigned IdiomsMagicDivMod::divisorByMagicNumberSigned3(unsigned magic_number, unsigned shift)
{
	llvm::APInt x, q, r, m(128, magic_number); // true = signed
	// Set n to 0xFFFFFFFF FFFFFFFF FFFFFFFF (i.e. 96 bits)
	x = x.getAllOnesValue(96).zext(128);
	q = (x * m).lshr(shift);
	if (q == 0)
		return 0;

	llvm::APInt::udivrem(x, q, q, r);
	uint32_t result = q.getLimitedValue(std::numeric_limits<uint32_t>::max());
	return r == 0 ? result : ++result /* ceil */;
}

/**
 * Calculate original divisor from `signed magic number multiplication' form.
 * ( value * magic + value ) >> ( 32 + shift )
 *
 * @param magic_number a magic number used when multiply
 * @param shift a shift after multiplication
 * @return computed divisor
 */
unsigned IdiomsMagicDivMod::divisorByMagicNumberSigned4(unsigned magic_number, unsigned shift)
{
	llvm::APInt x, q, r, m(128, magic_number); // true = signed
	// Set n to 0xFFFFFFFF FFFFFFFF FFFFFFFF (i.e. 96 bits)
	x = x.getAllOnesValue(96).zext(128);
	q = (x * m + x).lshr(32 + shift);
	if (q == 0)
		return 0;

	llvm::APInt::udivrem(x, q, q, r);
	uint32_t result = q.getLimitedValue(std::numeric_limits<uint32_t>::max());
	return r == 0 ? result : ++result /* ceil*/;
}

/*******************************************************************************/

/**
 * Exchange (int32_t)((int64_t)X * (int64_t)magic_number >> N) with unsigned
 * division
 *
 * @param iter value to visit
 * @return replaced Instruction, otherwise nullptr
 */
Instruction * IdiomsMagicDivMod::magicUnsignedDiv1(BasicBlock::iterator iter) const {
	/*
	 * Derivation tree (gcc-arm, unsigned div 11):
	 *
	 *                    trunc to i32
	 *                         |
	 *                         |
	 *                        lshr
	 *                         /\
	 *                  -------  -------
	 *                 /                \
	 *               mul                <n>
	 *               /\
	 *           ----  ----
	 *          /          \
	 *    zext to i64   <magic const>
	 *         |
	 *         |
	 *         |
	 *       <var>
	 *
	 */
	Instruction & val = (*iter);
	Value * op_trunc   = nullptr;
	Value * op_lshr    = nullptr;
	Value * op_mul     = nullptr;
	Value * op_zext    = nullptr;
	Value * op_var     = nullptr;
	ConstantInt * cnst = nullptr;
	ConstantInt * mn   = nullptr;
	unsigned shift     = 0;

	if (! match(&val, m_Trunc(m_Value(op_lshr))))
		return nullptr;

	if (! match(op_lshr, m_LShr(m_Value(op_mul), m_ConstantInt(cnst))))
		return nullptr;

	shift = *cnst->getValue().getRawData();

	if (! match(op_mul, m_Mul(m_Value(op_zext), m_ConstantInt(mn)))
			&& ! match(op_mul, m_Mul(m_ConstantInt(mn), m_Value(op_zext))))
		return nullptr;

	if (! match(op_zext, m_ZExt(m_Value(op_var))))
		return nullptr;

	eraseInstFromBasicBlock(op_trunc, val.getParent());
	eraseInstFromBasicBlock(op_lshr, val.getParent());
	eraseInstFromBasicBlock(op_mul, val.getParent());
	eraseInstFromBasicBlock(op_zext, val.getParent());

	unsigned divisor = divisorByMagicNumberUnsigned2(*mn->getValue().getRawData(), shift);
	Constant *NewCst = ConstantInt::get(op_var->getType(), divisor);
	BinaryOperator *div = BinaryOperator::CreateUDiv(op_var, NewCst);

	// value and divisor have different types, conversion needed
	// conversion can be from to smaller or even bigger
	if (val.getType() != div->getType() && CastInst::castIsValid(Instruction::ZExt, div, val.getType())) {
		val.getParent()->getInstList().insert(iter, div);
		return CastInst::Create(Instruction::ZExt, div, val.getType());
	} else if (val.getType() != div->getType() && CastInst::castIsValid(Instruction::Trunc, div, val.getType())) {
		val.getParent()->getInstList().insert(iter, div);
		return CastInst::Create(Instruction::Trunc, div, val.getType());
	} else
		return div;
}

/**
 * Exchange
 *   int32_t y = 613566757 * (int64_t)x >> 32;
 *   res = ((x - y >> 1) + y) / 4;
 * with unsigned division
 *
 * @param iter value to visit
 * @return replaced Instruction, otherwise nullptr
 */
Instruction * IdiomsMagicDivMod::magicUnsignedDiv2(BasicBlock::iterator iter) const {
	/*
	 * Derivation tree (gcc-arm, unsigned div 7):
	 * There's only one mul, subtree is reused.
	 *
	 *                             lshr
	 *                              /\
	 *                          ----  ----
	 *                         /          \
	 *                       add        <shift>
	 *                        /\
	 *                    ----  ---------------
	 *                   /                     \
	 *                 lshr                   trunc
	 *                  /\                      |
	 *              ----  ----                  |
	 *             /          \                 |
	 *           sub           1                |
	 *           /\                            lshr (subtree is same as in trunc*)
	 *       ----  ----                         /\
	 *      /          \                    ----  ----
	 *   <var>        trunc*               /          \
	 *                  |                 mul         32
	 *                  |                 /\
	 *                 lshr           ----  ----
	 *                  /\           /          \
	 *              ----  ----     zext   <magic_number>
	 *             /          \     |
	 *           mul          32    |
	 *           /\               <var>
	 *       ----  ----
	 *      /          \
	 *    zext    <magic_number>
	 *      |
	 *      |
	 *    <var>
	 */
	Instruction & val = (*iter);
	Value * op_trunc    = nullptr;
	Value * op_lshr1    = nullptr;
	Value * op_lshr2    = nullptr;
	Value * op_lshr_tmp = nullptr;
	Value * op_mul      = nullptr;
	Value * op_zext     = nullptr;
	Value * op_var      = nullptr;
	Value * op_sub      = nullptr;
	Value * op_add      = nullptr;
	ConstantInt * cnst  = nullptr;
	ConstantInt * mn    = nullptr;
	unsigned shift      = 0;

	if (! match(&val, m_LShr(m_Value(op_add), m_ConstantInt(cnst))))
		return nullptr;

	shift = *cnst->getValue().getRawData();

	if (! match(op_add, m_Add(m_Value(op_lshr1), m_Value(op_trunc))))
		return nullptr;

	// LHS of add
	if (! match(op_lshr1, m_LShr(m_Value(op_sub), m_ConstantInt(cnst))))
		return nullptr;

	unsigned shift2 = *cnst->getValue().getRawData();

	if (! match(op_sub, m_Sub(m_Value(op_var), m_Value(op_trunc))))
		return nullptr;

	if (! match(op_trunc, m_Trunc(m_Value(op_lshr2))))
		return nullptr;

	if (! match(op_lshr2, m_LShr(m_Value(op_mul), m_ConstantInt(cnst)))
			|| *cnst->getValue().getRawData() != 32)
		return nullptr;

	if (! match(op_mul, m_Mul(m_Value(op_zext), m_ConstantInt(mn)))
			&& ! match(op_mul, m_Mul(m_ConstantInt(mn), m_Value(op_zext))))
		return nullptr;

	if (! match(op_zext, m_ZExt(m_Value(op_var))))
		return nullptr;

	// RHS of add
	// Check only root of subtree, it is reused, so we know what instructions
	// are here...
	if (! match(op_trunc, m_Trunc(m_Value(op_lshr_tmp))))
		return nullptr;

	if (op_lshr_tmp != op_lshr2)
		return nullptr;

	eraseInstFromBasicBlock(op_sub, val.getParent());
	eraseInstFromBasicBlock(op_trunc, val.getParent());
	eraseInstFromBasicBlock(op_lshr1, val.getParent());
	eraseInstFromBasicBlock(op_lshr2, val.getParent());
	eraseInstFromBasicBlock(op_mul, val.getParent());
	eraseInstFromBasicBlock(op_zext, val.getParent());

	unsigned divisor = divisorByMagicNumberUnsigned(*mn->getValue().getRawData(), shift2, shift);
	Constant *NewCst = ConstantInt::get(op_var->getType(), divisor);
	BinaryOperator *div = BinaryOperator::CreateUDiv(op_var, NewCst);

	// value and divisor have different types, conversion needed
	// conversion can be from to smaller or even bigger
	if (val.getType() != div->getType() && CastInst::castIsValid(Instruction::ZExt, div, val.getType())) {
		val.getParent()->getInstList().insert(iter, div);
		return CastInst::Create(Instruction::ZExt, div, val.getType());
	} else if (val.getType() != div->getType() && CastInst::castIsValid(Instruction::Trunc, div, val.getType())) {
		val.getParent()->getInstList().insert(iter, div);
		return CastInst::Create(Instruction::Trunc, div, val.getType());
	} else
		return div;
}

/**
 * Exchange
 *   ((int32_t)((int64_t)magic_number * (int64_t)X >> 32) + X >> N) - (x >> 31))
 * with signed division
 *
 * @param iter value to visit
 * @return replaced Instruction, otherwise nullptr
 */
Instruction * IdiomsMagicDivMod::magicSignedDiv1(BasicBlock::iterator iter) const {
	/*
	 * Derivation tree (gcc-arm, signed div 15):
	 *
	 *                                    sub
	 *                                     /\
	 *                              -------  -------
	 *                             /                \
	 *                           ashr               ashr
	 *                           /\                  /\
	 *                       ----  ----          ----  ----
	 *                      /          \        /          \
	 *                  add i32      shift   <var>         31
	 *                      |\
	 *                      | -------
	 *                      |        \
	 *                     lshr     <var>
	 *                      /\
	 *                  ----  ----
	 *                 /          \
	 *               mul          32
	 *               /\
	 *           ----  ----
	 *          /          \
	 *     sext to i64    <var>
	 *         |
	 *         |
	 *  <magic const>
	 *
	 */
	Instruction & val = (*iter);
	Value * op_ashr1   = nullptr;
	Value * op_ashr2   = nullptr;
	Value * op_trunc   = nullptr;
	Value * op_lshr    = nullptr;
	Value * op_mul     = nullptr;
	Value * op_sext    = nullptr;
	Value * op_var     = nullptr;
	Value * op_add     = nullptr;
	ConstantInt * cnst = nullptr;
	ConstantInt * mn   = nullptr;
	unsigned shift     = 0;

	if (! match(&val, m_Sub(m_Value(op_ashr1), m_Value(op_ashr2))))
		return nullptr;

	// RHS of sub
	if (! match(op_ashr2, m_AShr(m_Value(op_var), m_ConstantInt(cnst)))
			|| *cnst->getValue().getRawData() != 31)
		return nullptr;

	// LHS of sub
	if (! match(op_ashr1, m_AShr(m_Value(op_add), m_ConstantInt(cnst))))
		return nullptr;

	shift = *cnst->getValue().getRawData();

	if (! match(op_add, m_Add(m_Value(op_trunc), m_Value(op_var))))
		return nullptr;

	if (! match(op_trunc, m_Trunc(m_Value(op_lshr))))
		return nullptr;

	if (! match(op_lshr, m_LShr(m_Value(op_mul), m_ConstantInt(cnst)))
			|| *cnst->getValue().getRawData() != 32)
		return nullptr;

	if (! match(op_mul, m_Mul(m_Value(op_sext), m_ConstantInt(mn)))
			&& ! match(op_mul, m_Mul(m_ConstantInt(mn), m_Value(op_sext))))
		return nullptr;

	if (! match(op_sext, m_SExt(m_Value(op_var))))
		return nullptr;

	eraseInstFromBasicBlock(op_ashr1, val.getParent());
	eraseInstFromBasicBlock(op_ashr2, val.getParent());
	eraseInstFromBasicBlock(op_trunc, val.getParent());
	eraseInstFromBasicBlock(op_lshr, val.getParent());
	eraseInstFromBasicBlock(op_mul, val.getParent());
	eraseInstFromBasicBlock(op_add, val.getParent());
	eraseInstFromBasicBlock(op_sext, val.getParent());

	int divisor = divisorByMagicNumberSigned2(*mn->getValue().getRawData(), shift);

	Constant *NewCst = ConstantInt::get(op_var->getType(), divisor);
	BinaryOperator *div = BinaryOperator::CreateSDiv(op_var, NewCst);

	// value and divisor have different types, conversion needed
	// conversion can be from to smaller or even bigger
	if (val.getType() != div->getType() && CastInst::castIsValid(Instruction::ZExt, div, val.getType())) {
		val.getParent()->getInstList().insert(iter, div);
		return CastInst::Create(Instruction::ZExt, div, val.getType());
	} else if (val.getType() != div->getType() && CastInst::castIsValid(Instruction::Trunc, div, val.getType())) {
		val.getParent()->getInstList().insert(iter, div);
		return CastInst::Create(Instruction::Trunc, div, val.getType());
	} else
		return div;
}

/**
 * Exchange
 *   ((int32_t)((int64_t)magic_number * (int64_t)X >> 32) >> 1) - (x >> 31))
 * with signed division
 *
 * @param iter value to visit
 * @return replaced Instruction, otherwise nullptr
 */
Instruction * IdiomsMagicDivMod::magicSignedDiv2(BasicBlock::iterator iter) const {
	/*
	 * Derivation tree (gcc-arm, signed div 11, add is omitted):
	 *
	 *                                    sub
	 *                                     /\
	 *                              -------  -------
	 *                             /                \
	 *                           ashr               ashr
	 *                           /\                  /\
	 *                       ----  ----          ----  ----
	 *                      /           \       /          \
	 *               trunc to i32       <n>   <var>        31
	 *                     |
	 *                     |
	 *                    lshr
	 *                     /\
	 *                 ----  ----
	 *                /          \
	 *              mul          32
	 *              /\
	 *          ----  ----
	 *         /          \
	 *    sext to i64    <var>
	 *        |
	 *        |
	 *  <magic const>
	 *
	 */

	Instruction & val = (*iter);
	Value * op_ashr1   = nullptr;
	Value * op_ashr2   = nullptr;
	Value * op_trunc   = nullptr;
	Value * op_lshr    = nullptr;
	Value * op_mul     = nullptr;
	Value * op_sext    = nullptr;
	Value * op_var     = nullptr;
	ConstantInt * cnst = nullptr;
	ConstantInt * mn   = nullptr;
	unsigned shift     = 0;

	if (! match(&val, m_Sub(m_Value(op_ashr1), m_Value(op_ashr2))))
		return nullptr;

	// RHS of sub
	if (! match(op_ashr2, m_AShr(m_Value(op_var), m_ConstantInt(cnst)))
			|| *cnst->getValue().getRawData() != 31)
		return nullptr;

	// LHS of sub
	if (! match(op_ashr1, m_AShr(m_Value(op_trunc), m_ConstantInt(cnst))))
		return nullptr;

	shift = *cnst->getValue().getRawData();

	if (! match(op_trunc, m_Trunc(m_Value(op_lshr))))
		return nullptr;

	if (! match(op_lshr, m_LShr(m_Value(op_mul), m_ConstantInt(cnst)))
			|| *cnst->getValue().getRawData() != 32)
		return nullptr;

	if (! match(op_mul, m_Mul(m_Value(op_sext), m_ConstantInt(mn)))
			&& ! match(op_mul, m_Mul(m_ConstantInt(mn), m_Value(op_sext))))
		return nullptr;

	if (! match(op_sext, m_SExt(m_Value(op_var))))
		return nullptr;

	eraseInstFromBasicBlock(op_ashr1, val.getParent());
	eraseInstFromBasicBlock(op_ashr2, val.getParent());
	eraseInstFromBasicBlock(op_trunc, val.getParent());
	eraseInstFromBasicBlock(op_lshr, val.getParent());
	eraseInstFromBasicBlock(op_mul, val.getParent());
	eraseInstFromBasicBlock(op_sext, val.getParent());

	int divisor = divisorByMagicNumberSigned(*mn->getValue().getRawData(), shift);

	Constant *NewCst = ConstantInt::get(op_var->getType(), divisor);
	BinaryOperator *div = BinaryOperator::CreateSDiv(op_var, NewCst);

	// value and divisor have different types, conversion needed
	// conversion can be from to smaller or even bigger
	if (val.getType() != div->getType() && CastInst::castIsValid(Instruction::ZExt, div, val.getType())) {
		val.getParent()->getInstList().insert(iter, div);
		return CastInst::Create(Instruction::ZExt, div, val.getType());
	} else if (val.getType() != div->getType() && CastInst::castIsValid(Instruction::Trunc, div, val.getType())) {
		val.getParent()->getInstList().insert(iter, div);
		return CastInst::Create(Instruction::Trunc, div, val.getType());
	} else
		return div;
}

/**
 * Exchange
 *   (x >> 31) - ((int32_t)(magic_number * (int64_t)x >> 32) >> shift)
 * with signed division
 *
 * @param iter value to visit
 * @return replaced Instruction, otherwise nullptr
 */
Instruction * IdiomsMagicDivMod::magicSignedDiv3(BasicBlock::iterator iter) const {
	/*
	 * This is similar version to magicSignedDiv2, but the sign of the division
	 * is negative!
	 *
	 * Derivation tree (gcc-arm, signed div -20, add is omitted):
	 *
	 *                   sub
	 *                    /\
	 *             -------  -------
	 *            /                \
	 *          ashr               ashr
	 *          /\                  /\
	 *      ----  ----          ----  ----
	 *     /           \       /          \
	 *  <var>          31   trunc       <shift>
	 *                        |
	 *                        |
	 *                      lshr
	 *                       /\
	 *                   ----  ----
	 *                  /          \
	 *                mul          32
	 *                /\
	 *            ----  ----
	 *           /          \
	 *         sext    <magic const>
	 *          |
	 *          |
	 *        <var>
	 */

	Instruction & val = (*iter);
	Value * op_ashr1   = nullptr;
	Value * op_ashr2   = nullptr;
	Value * op_trunc   = nullptr;
	Value * op_lshr    = nullptr;
	Value * op_mul     = nullptr;
	Value * op_sext    = nullptr;
	Value * op_var     = nullptr;
	ConstantInt * cnst = nullptr;
	ConstantInt * mn   = nullptr;
	unsigned shift     = 0;

	if (! match(&val, m_Sub(m_Value(op_ashr1), m_Value(op_ashr2))))
		return nullptr;

	// LHS of sub
	if (! match(op_ashr1, m_AShr(m_Value(op_var), m_ConstantInt(cnst)))
			|| *cnst->getValue().getRawData() != 31)
		return nullptr;

	// RHS of sub
	if (! match(op_ashr2, m_AShr(m_Value(op_trunc), m_ConstantInt(cnst))))
		return nullptr;

	shift = *cnst->getValue().getRawData();

	if (! match(op_trunc, m_Trunc(m_Value(op_lshr))))
		return nullptr;

	if (! match(op_lshr, m_LShr(m_Value(op_mul), m_ConstantInt(cnst)))
			|| *cnst->getValue().getRawData() != 32)
		return nullptr;

	if (! match(op_mul, m_Mul(m_Value(op_sext), m_ConstantInt(mn)))
			&& ! match(op_mul, m_Mul(m_ConstantInt(mn), m_Value(op_sext))))
		return nullptr;

	if (! match(op_sext, m_SExt(m_Value(op_var))))
		return nullptr;

	eraseInstFromBasicBlock(op_ashr1, val.getParent());
	eraseInstFromBasicBlock(op_ashr2, val.getParent());
	eraseInstFromBasicBlock(op_trunc, val.getParent());
	eraseInstFromBasicBlock(op_lshr, val.getParent());
	eraseInstFromBasicBlock(op_mul, val.getParent());
	eraseInstFromBasicBlock(op_sext, val.getParent());

	// note negative sign!
	int divisor = - divisorByMagicNumberSigned(*mn->getValue().getRawData(), shift);

	Constant *NewCst = ConstantInt::get(op_var->getType(), divisor);
	BinaryOperator *div = BinaryOperator::CreateSDiv(op_var, NewCst);

	// value and divisor have different types, conversion needed
	// conversion can be from to smaller or even bigger
	if (val.getType() != div->getType() && CastInst::castIsValid(Instruction::ZExt, div, val.getType())) {
		val.getParent()->getInstList().insert(iter, div);
		return CastInst::Create(Instruction::ZExt, div, val.getType());
	} else if (val.getType() != div->getType() && CastInst::castIsValid(Instruction::Trunc, div, val.getType())) {
		val.getParent()->getInstList().insert(iter, div);
		return CastInst::Create(Instruction::Trunc, div, val.getType());
	} else
		return div;
}

/**
 * Exchange
 *   (x >> 31) - ((int32_t)(magic_number * (int64_t)x >> 32) + x >> shift)
 * with signed division
 *
 * @param iter value to visit
 * @return replaced Instruction, otherwise nullptr
 */
Instruction * IdiomsMagicDivMod::magicSignedDiv4(BasicBlock::iterator iter) const {
	/*
	 * This is similar version to magicSignedDiv1, but the sign of the division
	 * is negative!
	 *
	 * Derivation tree (gcc-arm, signed div -29):
	 *
	 *                   sub
	 *                    /\
	 *             -------  -------
	 *            /                \
	 *          ashr               ashr
	 *          /\                  /\
	 *      ----  ----          ----  ----
	 *     /           \       /          \
	 *  <var>          31    add       <shift>
	 *                       /\
	 *                   ----  ----
	 *                  /          \
	 *                lshr        <var>
	 *                 /\
	 *             ----  ----
	 *            /          \
	 *          mul          32
	 *          /\
	 *      ----  ----
	 *     /          \
	 *   sext    <magic const>
	 *    |
	 *    |
	 *  <var>
	 */
	Instruction & val = (*iter);
	Value * op_ashr1   = nullptr;
	Value * op_ashr2   = nullptr;
	Value * op_trunc   = nullptr;
	Value * op_lshr    = nullptr;
	Value * op_mul     = nullptr;
	Value * op_sext    = nullptr;
	Value * op_var     = nullptr;
	Value * op_add     = nullptr;
	ConstantInt * cnst = nullptr;
	ConstantInt * mn   = nullptr;
	unsigned shift     = 0;

	if (! match(&val, m_Sub(m_Value(op_ashr1), m_Value(op_ashr2))))
		return nullptr;

	// LHS of sub
	if (! match(op_ashr1, m_AShr(m_Value(op_var), m_ConstantInt(cnst)))
			|| *cnst->getValue().getRawData() != 31)
		return nullptr;

	// RHS of sub
	if (! match(op_ashr2, m_AShr(m_Value(op_add), m_ConstantInt(cnst))))
		return nullptr;

	shift = *cnst->getValue().getRawData();

	if (! match(op_add, m_Add(m_Value(op_trunc), m_Value(op_var))))
		return nullptr;

	if (! match(op_trunc, m_Trunc(m_Value(op_lshr))))
		return nullptr;

	if (! match(op_lshr, m_LShr(m_Value(op_mul), m_ConstantInt(cnst)))
			|| *cnst->getValue().getRawData() != 32)
		return nullptr;

	if (! match(op_mul, m_Mul(m_Value(op_sext), m_ConstantInt(mn)))
			&& ! match(op_mul, m_Mul(m_ConstantInt(mn), m_Value(op_sext))))
		return nullptr;

	if (! match(op_sext, m_SExt(m_Value(op_var))))
		return nullptr;

	eraseInstFromBasicBlock(op_ashr1, val.getParent());
	eraseInstFromBasicBlock(op_ashr2, val.getParent());
	eraseInstFromBasicBlock(op_trunc, val.getParent());
	eraseInstFromBasicBlock(op_lshr, val.getParent());
	eraseInstFromBasicBlock(op_mul, val.getParent());
	eraseInstFromBasicBlock(op_sext, val.getParent());
	eraseInstFromBasicBlock(op_add, val.getParent());

	// note negative sign!
	int divisor = - divisorByMagicNumberSigned2(*mn->getValue().getRawData(), shift);

	Constant *NewCst = ConstantInt::get(op_var->getType(), divisor);
	BinaryOperator *div = BinaryOperator::CreateSDiv(op_var, NewCst);

	// value and divisor have different types, conversion needed
	// conversion can be from to smaller or even bigger
	if (val.getType() != div->getType() && CastInst::castIsValid(Instruction::ZExt, div, val.getType())) {
		val.getParent()->getInstList().insert(iter, div);
		return CastInst::Create(Instruction::ZExt, div, val.getType());
	} else if (val.getType() != div->getType() && CastInst::castIsValid(Instruction::Trunc, div, val.getType())) {
		val.getParent()->getInstList().insert(iter, div);
		return CastInst::Create(Instruction::Trunc, div, val.getType());
	} else
		return div;
}

/**
 * Exchange
 *   (x >> 31) - (int32_t)(magic_number * (int64_t)x >> 32)
 * with signed division
 *
 * @param iter value to visit
 * @return replaced Instruction, otherwise nullptr
 */
Instruction * IdiomsMagicDivMod::magicSignedDiv5(BasicBlock::iterator iter) const {
	/*
	 * This is similar version to magicSignedDiv2, but the sign of the division
	 * is negative!
	 *
	 * Derivation tree (gcc-arm, signed div -3, add is omitted):
	 *
	 *                   sub
	 *                    /\
	 *             -------  -------
	 *            /                \
	 *          ashr               trunc
	 *          /\                   |
	 *      ----  ----               |
	 *     /           \           lshr
	 *  <var>          31           /\
	 *                          ----  ----
	 *                         /          \
	 *                       mul          32
	 *                       /\
	 *                   ----  ----
	 *                  /          \
	 *                sext    <magic const>
	 *                 |
	 *                 |
	 *               <var>
	 */

	Instruction & val = (*iter);
	Value * op_trunc   = nullptr;
	Value * op_lshr    = nullptr;
	Value * op_ashr    = nullptr;
	Value * op_mul     = nullptr;
	Value * op_sext    = nullptr;
	Value * op_var     = nullptr;
	ConstantInt * cnst = nullptr;
	ConstantInt * mn   = nullptr;

	if (! match(&val, m_Sub(m_Value(op_ashr), m_Value(op_trunc))))
		return nullptr;

	// LHS of sub
	if (! match(op_ashr, m_AShr(m_Value(op_var), m_ConstantInt(cnst)))
			|| *cnst->getValue().getRawData() != 31)
		return nullptr;

	// RHS of sub
	if (! match(op_trunc, m_Trunc(m_Value(op_lshr))))
		return nullptr;

	if (! match(op_lshr, m_LShr(m_Value(op_mul), m_ConstantInt(cnst)))
			|| *cnst->getValue().getRawData() != 32)
		return nullptr;

	if (! match(op_mul, m_Mul(m_Value(op_sext), m_ConstantInt(mn)))
			&& ! match(op_mul, m_Mul(m_ConstantInt(mn), m_Value(op_sext))))
		return nullptr;

	if (! match(op_sext, m_SExt(m_Value(op_var))))
		return nullptr;

	eraseInstFromBasicBlock(op_ashr, val.getParent());
	eraseInstFromBasicBlock(op_trunc, val.getParent());
	eraseInstFromBasicBlock(op_lshr, val.getParent());
	eraseInstFromBasicBlock(op_mul, val.getParent());
	eraseInstFromBasicBlock(op_sext, val.getParent());

	// note negative sign!
	int divisor = - divisorByMagicNumberSigned(*mn->getValue().getRawData(), 0);

	Constant *NewCst = ConstantInt::get(op_var->getType(), divisor);
	BinaryOperator *div = BinaryOperator::CreateSDiv(op_var, NewCst);

	// value and divisor have different types, conversion needed
	// conversion can be from to smaller or even bigger
	if (val.getType() != div->getType() && CastInst::castIsValid(Instruction::ZExt, div, val.getType())) {
		val.getParent()->getInstList().insert(iter, div);
		return CastInst::Create(Instruction::ZExt, div, val.getType());
	} else if (val.getType() != div->getType() && CastInst::castIsValid(Instruction::Trunc, div, val.getType())) {
		val.getParent()->getInstList().insert(iter, div);
		return CastInst::Create(Instruction::Trunc, div, val.getType());
	} else
		return div;
}

/**
 * Exchange
 *   (x >> 31) - (int32_t)(magic_number * (int64_t)x >> 32)
 * with signed division
 *
 * @param iter value to visit
 * @return replaced Instruction, otherwise nullptr
 */
Instruction * IdiomsMagicDivMod::magicSignedDiv6(BasicBlock::iterator iter) const {
	/*
	 * Derivation tree (gcc-arm, signed div 3, add is omitted):
	 *
	 *                              sub
	 *                               /\
	 *                        -------  -------
	 *                       /                \
	 *                    trunc               ashr
	 *                      |                  /\
	 *                      |              ----  ----
	 *                     lshr           /          \
	 *                      /\          <var>        31
	 *                  ----  ----
	 *                 /          \
	 *               mul          32
	 *               /\
	 *           ----  ----
	 *          /          \
	 *     sext to i64    <var>
	 *         |
	 *         |
	 *   <magic const>
	 *
	 */

	Instruction & val = (*iter);
	Value * op_ashr2   = nullptr;
	Value * op_trunc   = nullptr;
	Value * op_lshr    = nullptr;
	Value * op_mul     = nullptr;
	Value * op_sext    = nullptr;
	Value * op_var     = nullptr;
	ConstantInt * cnst = nullptr;
	ConstantInt * mn   = nullptr;

	if (! match(&val, m_Sub(m_Value(op_trunc), m_Value(op_ashr2))))
		return nullptr;

	// RHS of sub
	if (! match(op_ashr2, m_AShr(m_Value(op_var), m_ConstantInt(cnst)))
			|| *cnst->getValue().getRawData() != 31)
		return nullptr;

	// LHS of sub
	if (! match(op_trunc, m_Trunc(m_Value(op_lshr))))
		return nullptr;

	if (! match(op_lshr, m_LShr(m_Value(op_mul), m_ConstantInt(cnst)))
			|| *cnst->getValue().getRawData() != 32)
		return nullptr;

	if (! match(op_mul, m_Mul(m_Value(op_sext), m_ConstantInt(mn)))
			&& ! match(op_mul, m_Mul(m_ConstantInt(mn), m_Value(op_sext))))
		return nullptr;

	if (! match(op_sext, m_SExt(m_Value(op_var))))
		return nullptr;

	eraseInstFromBasicBlock(op_ashr2, val.getParent());
	eraseInstFromBasicBlock(op_trunc, val.getParent());
	eraseInstFromBasicBlock(op_lshr, val.getParent());
	eraseInstFromBasicBlock(op_mul, val.getParent());
	eraseInstFromBasicBlock(op_sext, val.getParent());

	int divisor = divisorByMagicNumberSigned(*mn->getValue().getRawData(), 0);

	Constant *NewCst = ConstantInt::get(op_var->getType(), divisor);
	BinaryOperator *div = BinaryOperator::CreateSDiv(op_var, NewCst);

	// value and divisor have different types, conversion needed
	// conversion can be from to smaller or even bigger
	if (val.getType() != div->getType() && CastInst::castIsValid(Instruction::ZExt, div, val.getType())) {
		val.getParent()->getInstList().insert(iter, div);
		return CastInst::Create(Instruction::ZExt, div, val.getType());
	} else if (val.getType() != div->getType() && CastInst::castIsValid(Instruction::Trunc, div, val.getType())) {
		val.getParent()->getInstList().insert(iter, div);
		return CastInst::Create(Instruction::Trunc, div, val.getType());
	} else
		return div;
}

/**
 * Exchange
 *    ((int32_t)(v2 / 0x100000000) / -0x80000000 & -0x40000000 | (int32_t)(v2 / 0x400000000)) - (v1 / -0x80000000 & -2 | (int32_t)(v1 < 0));
 * with signed division
 *
 * @param iter value to visit
 * @param negative search for the negative divisor
 * @return replaced Instruction, otherwise nullptr
 */
Instruction * IdiomsMagicDivMod::magicSignedDiv7(BasicBlock::iterator iter, bool negative = false) const {
	/*
	 * Derivation tree (gcc-powerpc, signed div 10):
	 *
	 * There are multiple versions of this idiom with only minor changes.
	 * version 1) There's only one "mul", subtree is reused.
	 * version 2) Differs from version 1: there is no "ashr" in the LHS
	 * version 3) Differs from version 1: there's only one "trunc to i32", subtree is reused.
	 *
	 * version 1)
	 *                                                          sub
	 *                                                           /\
	 *                                            ---------------  ---------------
	 *                                           /                                \
	 *                                         or                                 or
	 *                                         /\                                 /\
	 *                                   ------  ------                     ------  ------
	 *                                  /              \                   /              \
	 *                                and         trunc to i32            and             lshr
	 *                                /\                |                 /\              /\
	 *                            ----  ----            |             ----  ----      ----  ----
	 *                           /          \         lshr           /          \    /          \
	 *                         ashr       <mask>        /\         ashr         -2  <var>       31
	 *                          /\                     /  \         /\
	 *                      ----  ----           ***mul <shift> ----  ----
	 *                     /          \                        /          \
	 *               trunc to i32     31                     <var>         31
	 *                    |
	 *                    |
	 *                   lshr
	 *                    /\
	 *                ----  ----
	 *               /          \
	 *           ***mul         32
	 *              /\
	 *          ----  ----
	 *         /          \
	 *  sext to i64  <magic const>
	 *        |
	 *        |
	 *     <var>
	 *
	 * version 2)
	 *                                                     sub
	 *                                                     /\
	 *                                      ---------------  ---------------
	 *                                     /                                \
	 *                                    or                                 or
	 *                                    /\                                 /\
	 *                              ------  ------                     ------  ------
	 *                             /              \                   /              \
	 *                           and         trunc to i32            and            lshr
	 *                           /\                |                 /\              /\
	 *                       ----  ----            |             ----  ----      ----  ----
	 *                      /          \         lshr           /          \    /          \
	 *               trunc to i32   <mask>        /\         ashr         -2  <var>       31
	 *                     |                     /  \         /\
	 *                     |               ***mul <shift> ----  ----
	 *                    lshr                           /          \
	 *                    /\                          <var>         31
	 *                ----  ----
	 *               /          \
	 *           ***mul         32
	 *              /\
	 *          ----  ----
	 *         /          \
	 *  sext to i64  <magic const>
	 *        |
	 *        |
	 *     <var>
	 *
	 * version 3)
	 *                                                          sub
	 *                                                           /\
	 *                                            ---------------  ---------------
	 *                                           /                                \
	 *                                         or                                 or
	 *                                         /\                                 /\
	 *                                   ------  ------                     ------  ------
	 *                                  /              \                   /              \
	 *                                and              lshr               and             lshr
	 *                                /\                /\                /\              /\
	 *                            ----  ----           /  \           ----  ----      ----  ----
	 *                           /          \    ***add  <shift>     /          \    /          \
	 *                         ashr       <mask>                   ashr        -2  <var>       31
	 *                          /\                                  /\
	 *                      ----  ----                          ----  ----
	 *                     /          \                        /          \
	 *                ***add          31                     <var>         31
	 *                    /\
	 *                ----  ----
	 *               /          \
	 *         trunc to i32    <var>
	 *               |
	 *               |
	 *              lshr
	 *               /\
	 *           ----  ----
	 *          /          \
	 *         mul         32
	 *         /\
	 *    ----  ----
	 *   /          \
	 * sext to i64  <magic const>
	 *  |
	 *  |
	 * <var>
	 */

	Instruction & val = (*iter);
	Value * op_or1      = nullptr;
	Value * op_or2      = nullptr;
	Value * op_add      = nullptr;
	Value * op_add_tmp  = nullptr;
	Value * op_and1     = nullptr;
	Value * op_and2     = nullptr;
	Value * op_lshr1    = nullptr;
	Value * op_lshr2    = nullptr;
	Value * op_lshr3    = nullptr;
	Value * op_ashr1    = nullptr;
	Value * op_trun_or_ashr = nullptr;
	Value * op_var      = nullptr;
	Value * op_mul      = nullptr;
	Value * op_mul_tmp  = nullptr;
	Value * op_trun_or_lshr = nullptr;
	Value * op_trunc    = nullptr;
	Value * op_sext     = nullptr;
	ConstantInt * cnst  = nullptr;
	int version         = 0;
	int divisor         = 0;
	unsigned magic      = 0;
	unsigned shift      = 0;

	if (negative)
	{ // The negative divisor has swapped subtrees op_or1 and op_or2.
		if (! match(&val, m_Sub(m_Value(op_or2), m_Value(op_or1))))
			return nullptr;
	}
	else
	{
		if (! match(&val, m_Sub(m_Value(op_or1), m_Value(op_or2))))
			return nullptr;
	}

	// RHS of sub
	if (! match(op_or2, m_Or(m_Value(op_and1), m_Value(op_lshr1))))
		return nullptr;

	if (! match(op_lshr1, m_LShr(m_Value(op_var), m_ConstantInt(cnst)))
			|| *cnst->getValue().getRawData() != 31)
		return nullptr;

	if (! match(op_and1, m_And(m_Value(op_ashr1), m_ConstantInt(cnst)))
			|| static_cast<signed>(*cnst->getValue().getRawData()) != -2)
		return nullptr;

	if (! match(op_ashr1, m_AShr(m_Value(op_var), m_ConstantInt(cnst)))
			|| *cnst->getValue().getRawData() != 31)
		return nullptr;

	// LHS of sub
	if (! match(op_or1, m_Or(m_Value(op_and2), m_Value(op_trun_or_lshr))))
		return nullptr;

	// RHS of the left OR (or1)
	// Check only roots of subtrees, they will be reused, so we know what
	// instructions are in here...
	if (match(op_trun_or_lshr, m_Trunc(m_Value(op_lshr3))))
	{
		// It can be version 1 or 2
		version = 12;
		if (! match(op_lshr3, m_LShr(m_Value(op_mul_tmp), m_ConstantInt(cnst))))
			return nullptr;

		shift = *cnst->getValue().getRawData();
	}
	else if (match(op_trun_or_lshr, m_LShr(m_Value(op_add_tmp), m_ConstantInt(cnst))))
	{
		version = 3;
		shift = *cnst->getValue().getRawData();
	}
	else
		return nullptr;

	// LHS of the left OR (or1)
	if (! match(op_and2, m_And(m_Value(op_trun_or_ashr), m_ConstantInt(cnst))))
		return nullptr;

	// In version 3, there is another ADD node that has to be handled
	if (version == 12)
	{
		if (match(op_trun_or_ashr, m_AShr(m_Value(op_trunc), m_ConstantInt(cnst)))
				&& *cnst->getValue().getRawData() == 31)
		{ // ashr node
			version = 1;
			if (! match(op_trunc, m_Trunc(m_Value(op_lshr2))))
				return nullptr;
		}
		else if (match(op_trun_or_ashr, m_Trunc(m_Value(op_lshr2))))
		{ // trunc node
			version = 2;
		}
		else
			return nullptr;
	}
	else if (version == 3)
	{
		if (! match(op_trun_or_ashr, m_AShr(m_Value(op_add), m_ConstantInt(cnst)))
				|| *cnst->getValue().getRawData() != 31)
			return nullptr;
		if (! match(op_add, m_Add(m_Value(op_trunc), m_Value(op_var))))
			return nullptr;
		if (! match(op_trunc, m_Trunc(m_Value(op_lshr2))))
			return nullptr;
	}

	if (! match(op_lshr2, m_LShr(m_Value(op_mul), m_ConstantInt(cnst)))
			|| *cnst->getValue().getRawData() != 32)
		return nullptr;

	if (! match(op_mul, m_Mul(m_Value(op_sext), m_ConstantInt(cnst)))
			&& ! match(op_mul, m_Mul(m_ConstantInt(cnst), m_Value(op_sext))))
		return nullptr;

	magic = static_cast<unsigned>(*cnst->getValue().getRawData());

	if (! match(op_sext, m_SExt(m_Value(op_var))))
		return nullptr;

	if (version == 1 || version == 2)
	{
		if (op_mul != op_mul_tmp)
			return nullptr;

		if (negative) // note negative sign!
			divisor = - divisorByMagicNumberSigned3(magic, shift);
		else
			divisor = divisorByMagicNumberSigned3(magic, shift);

		eraseInstFromBasicBlock(op_lshr3, val.getParent());
	}
	else if (version == 3)
	{
		if (op_add != op_add_tmp)
			return nullptr;

		if (negative) // note negative sign!
			divisor = - divisorByMagicNumberSigned4(magic, shift);
		else
			divisor = divisorByMagicNumberSigned4(magic, shift);

		eraseInstFromBasicBlock(op_add, val.getParent());
	}
	else
		return nullptr;

	eraseInstFromBasicBlock(op_or1, val.getParent());
	eraseInstFromBasicBlock(op_or2, val.getParent());
	eraseInstFromBasicBlock(op_and1, val.getParent());
	eraseInstFromBasicBlock(op_and2, val.getParent());
	eraseInstFromBasicBlock(op_lshr1, val.getParent());
	eraseInstFromBasicBlock(op_lshr2, val.getParent());
	eraseInstFromBasicBlock(op_ashr1, val.getParent());
	eraseInstFromBasicBlock(op_trun_or_ashr, val.getParent());
	eraseInstFromBasicBlock(op_trun_or_lshr, val.getParent());
	eraseInstFromBasicBlock(op_mul, val.getParent());
	eraseInstFromBasicBlock(op_trunc, val.getParent());
	eraseInstFromBasicBlock(op_sext, val.getParent());

	Constant *NewCst = ConstantInt::get(op_var->getType(), divisor);
	BinaryOperator *div = BinaryOperator::CreateSDiv(op_var, NewCst);

	// value and divisor have different types, conversion needed
	// conversion can be from to smaller or even bigger
	if (val.getType() != div->getType() && CastInst::castIsValid(Instruction::ZExt, div, val.getType())) {
		val.getParent()->getInstList().insert(iter, div);
		return CastInst::Create(Instruction::ZExt, div, val.getType());
	} else if (val.getType() != div->getType() && CastInst::castIsValid(Instruction::Trunc, div, val.getType())) {
		val.getParent()->getInstList().insert(iter, div);
		return CastInst::Create(Instruction::Trunc, div, val.getType());
	} else
		return div;
}

/**
 * Wrapper of magicSignedDiv7 for positive values.
 *
 * @param iter value to visit
 * @return replaced Instruction, otherwise nullptr
 */
Instruction * IdiomsMagicDivMod::magicSignedDiv7pos(BasicBlock::iterator iter) const {
	/*
	 * Derivation tree (gcc-powerpc, signed div 10):
	 *
	 * It is the same idiom as in magicSignedDiv7neg except the "or" subtrees
	 * are reversed.
	 */
	return magicSignedDiv7(iter, false);
}

/**
 * Wrapper of magicSignedDiv7 for negative values.
 *
 * @param iter value to visit
 * @return replaced Instruction, otherwise nullptr
 */
Instruction * IdiomsMagicDivMod::magicSignedDiv7neg(BasicBlock::iterator iter) const {
	/*
	 * Derivation tree (gcc-powerpc, signed div -10):
	 *
	 * It is the same idiom as in magicSignedDiv7pos except the "or" subtrees
	 * are reversed.
	 */
	return magicSignedDiv7(iter, true);
}

/**
 * Exchange
 *  int32_t v2 = v1 / -0x80000000; // 0x100004c0
 *  return (v2 & -0x20000000 | v1 / 8) - (v2 & -2 | (int32_t)(v1 < 0));
 * with signed division.
 * This is a similar version to magicSignedDiv7 except it is more simpler.
 *
 * @param iter value to visit
 * @param negative search for the negative divisor
 * @return replaced Instruction, otherwise nullptr
 */
Instruction * IdiomsMagicDivMod::magicSignedDiv8(BasicBlock::iterator iter, bool negative = false) const {
	/*
	 * Derivation tree (gcc-powerpc, signed div 15):
	 *
	 *                                    sub
	 *                                    /\
	 *                     ---------------  ---------------
	 *                    /                                \
	 *              trunc to i32                           or
	 *                    |                                /\
	 *                    |                          ------  ------
	 *                   lshr                       /              \
	 *                    /\                       and             lshr
	 *                ----  ----                   /\              /\
	 *               /          \              ----  ----      ----  ----
	 *              mul         32            /          \    /          \
	 *              /\                      ashr        -2  <var>        31
	 *         ----  ----                    /\
	 *        /          \               ----  ----
	 *      sext to i64  <magic const>  /          \
	 *       |                        <var>         31
	 *       |
	 *     <var>
	 *
	 */

	Instruction & val = (*iter);
	Value * op_or       = nullptr;
	Value * op_and      = nullptr;
	Value * op_lshr1    = nullptr;
	Value * op_lshr2    = nullptr;
	Value * op_ashr     = nullptr;
	Value * op_mul      = nullptr;
	Value * op_sext     = nullptr;
	Value * op_trunc    = nullptr;
	Value * op_var      = nullptr;
	ConstantInt * cnst  = nullptr;
	int divisor = 0;
	unsigned magic = 0;

	if (negative)
	{ // The negative divisor has swapped subtrees op_or and op_trunc.
		if (! match(&val, m_Sub(m_Value(op_or), m_Value(op_trunc))))
			return nullptr;
	}
	else
	{
		if (! match(&val, m_Sub(m_Value(op_trunc), m_Value(op_or))))
			return nullptr;
	}

	// RHS of sub
	if (! match(op_or, m_Or(m_Value(op_and), m_Value(op_lshr1))))
		return nullptr;

	if (! match(op_lshr1, m_LShr(m_Value(op_var), m_ConstantInt(cnst)))
			|| *cnst->getValue().getRawData() != 31)
		return nullptr;

	if (! match(op_and, m_And(m_Value(op_ashr), m_ConstantInt(cnst)))
			|| static_cast<signed>(*cnst->getValue().getRawData()) != -2)
		return nullptr;

	if (! match(op_ashr, m_AShr(m_Value(op_var), m_ConstantInt(cnst)))
			|| *cnst->getValue().getRawData() != 31)
		return nullptr;

	// LHS of sub
	if (! match(op_trunc, m_Trunc(m_Value(op_lshr2))))
		return nullptr;

	if (! match(op_lshr2, m_LShr(m_Value(op_mul), m_ConstantInt(cnst)))
			|| *cnst->getValue().getRawData() != 32)
		return nullptr;

	if (! match(op_mul, m_Mul(m_Value(op_sext), m_ConstantInt(cnst)))
			&& ! match(op_mul, m_Mul(m_ConstantInt(cnst), m_Value(op_sext))))
		return nullptr;

	magic = static_cast<unsigned>(*cnst->getValue().getRawData());

	if (! match(op_sext, m_SExt(m_Value(op_var))))
		return nullptr;

	if (negative) // note negative sign!
		divisor = - divisorByMagicNumberSigned3(magic, 32);
	else
		divisor = divisorByMagicNumberSigned3(magic, 32);

	eraseInstFromBasicBlock(op_or, val.getParent());
	eraseInstFromBasicBlock(op_and, val.getParent());
	eraseInstFromBasicBlock(op_lshr1, val.getParent());
	eraseInstFromBasicBlock(op_lshr2, val.getParent());
	eraseInstFromBasicBlock(op_ashr, val.getParent());
	eraseInstFromBasicBlock(op_mul, val.getParent());
	eraseInstFromBasicBlock(op_sext, val.getParent());
	eraseInstFromBasicBlock(op_trunc, val.getParent());

	Constant *NewCst = ConstantInt::get(op_var->getType(), divisor);
	BinaryOperator *div = BinaryOperator::CreateSDiv(op_var, NewCst);

	// value and divisor have different types, conversion needed
	// conversion can be from to smaller or even bigger
	if (val.getType() != div->getType() && CastInst::castIsValid(Instruction::ZExt, div, val.getType())) {
		val.getParent()->getInstList().insert(iter, div);
		return CastInst::Create(Instruction::ZExt, div, val.getType());
	} else if (val.getType() != div->getType() && CastInst::castIsValid(Instruction::Trunc, div, val.getType())) {
		val.getParent()->getInstList().insert(iter, div);
		return CastInst::Create(Instruction::Trunc, div, val.getType());
	} else
		return div;
}

/**
 * Wrapper of magicSignedDiv8 for positive values.
 *
 * @param iter value to visit
 * @return replaced Instruction, otherwise nullptr
 */
Instruction * IdiomsMagicDivMod::magicSignedDiv8pos(BasicBlock::iterator iter) const {
	/*
	 * Derivation tree (gcc-powerpc, signed div 6):
	 *
	 * It is the same idiom as in magicSignedDiv8neg except the subtrees
	 * of "sub" are reversed.
	 */
	return magicSignedDiv8(iter, false);
}

/**
 * Wrapper of magicSignedDiv8 for negative values.
 *
 * @param iter value to visit
 * @return replaced Instruction, otherwise nullptr
 */
Instruction * IdiomsMagicDivMod::magicSignedDiv8neg(BasicBlock::iterator iter) const {
	/*
	 * Derivation tree (gcc-powerpc, signed div -3):
	 *
	 * It is the same idiom as in magicSignedDiv8neg except the subtrees
	 * of "sub" are reversed.
	 */
	return magicSignedDiv8(iter, true);
}

/*
 * Exchange
 *   ((-k * magic_number * x) >> n) + x
 * with x % k
 *
 * @param iter value to visit
 * @return replaced Instruction, otherwise nullptr
 */
Instruction * IdiomsMagicDivMod::signedMod1(BasicBlock::iterator iter) const {
	/*
	 * Derivation tree (ARM/ELF):
	 *
	 *                                       add
	 *                                        /\
	 *                                 -------  -------
	 *                                /                \
	 *                                |                |
	 *                           trunc to i32*    zext to iXX  (or <x>)
	 *                                |                |
	 *                                |                |
	 *                               mul              <x>
	 *                               /\
	 *                        -------  -------
	 *                       /                \
	 *                    trunc*              <k>
	 *                      |
	 *                      |
	 *                     lshr
	 *                      /\
	 *                  ----  ----
	 *                 /          \
	 *               mul          32
	 *               /\
	 *           ----  ----
	 *          /          \
	 *     zext to i64    <magic const>
	 *         |
	 *         |
	 *        <x>
	 *
	 */

	Instruction & val         = (*iter);
	Value * op_trunc_or_else1 = nullptr;
	Value * op_trunc_or_else2 = nullptr;
	Value * op_mul1           = nullptr;
	Value * op_trunc_or_lshr  = nullptr;
	Value * op_lshr           = nullptr;
	Value * op_mul2           = nullptr;
	Value * op_zext2          = nullptr;
	Value * op_var            = nullptr;
	ConstantInt * cnst        = nullptr;
	ConstantInt * k           = nullptr;

	if (! match(&val, m_Add(m_Value(op_trunc_or_else1), m_Value(op_trunc_or_else2)))) {
		return nullptr;
	}

	if (! match(op_trunc_or_else1, m_ZExt(m_Value(op_var)))
		&& ! match(op_trunc_or_else2, m_ZExt(m_Value(op_var)))
		&& op_trunc_or_else1->getValueID() != Value::ValueTy::ArgumentVal
		&& op_trunc_or_else1->getValueID() != Value::ValueTy::GlobalVariableVal
		&& op_trunc_or_else1->getValueID() != Value::ValueTy::ConstantIntVal
		&& op_trunc_or_else2->getValueID() != Value::ValueTy::ArgumentVal
		&& op_trunc_or_else2->getValueID() != Value::ValueTy::GlobalVariableVal
		&& op_trunc_or_else2->getValueID() != Value::ValueTy::ConstantIntVal) {
		return nullptr;
	}

	if (match(op_trunc_or_else1, m_Trunc(m_Value(op_mul1)))
		|| match(op_trunc_or_else2, m_Trunc(m_Value(op_mul1)))) {
		// The first truncate
		if (! match(op_mul1, m_Mul(m_Value(op_trunc_or_lshr), m_ConstantInt(k)))
			&& ! match(op_mul1, m_Mul(m_ConstantInt(k), m_Value(op_trunc_or_lshr)))) {
			return nullptr;
		}
	} else if (! match(op_trunc_or_else1, m_Mul(m_Value(op_trunc_or_lshr), m_ConstantInt(k)))
			&& ! match(op_trunc_or_else1, m_Mul(m_ConstantInt(k), m_Value(op_trunc_or_lshr)))
			&& ! match(op_trunc_or_else2, m_Mul(m_Value(op_trunc_or_lshr), m_ConstantInt(k)))
			&& ! match(op_trunc_or_else2, m_Mul(m_ConstantInt(k), m_Value(op_trunc_or_lshr)))) {
		return nullptr;
	}

	if (! match(op_trunc_or_lshr, m_Trunc(m_Value(op_lshr)))) {
		// The second truncate
		op_lshr = op_trunc_or_lshr;
	}

	if (! match(op_lshr, m_LShr(m_Value(op_mul2), m_ConstantInt(cnst))))
		return nullptr;

	if (! match(op_mul2, m_Mul(m_Value(op_zext2), m_ConstantInt(cnst))))
		return nullptr;

	if (! match(op_zext2, m_ZExt(m_Value(op_var))))
		return nullptr;

	Constant *NewCst = ConstantInt::get(op_var->getType(), *k->getValue().getRawData());
	BinaryOperator *mod = BinaryOperator::CreateSRem(op_var, NewCst);

	// Do not erase the topmost nodes op_trunc_or_else1 and op_trunc_or_else2
	// they might be used for loading op_val value
	eraseInstFromBasicBlock(op_mul1, val.getParent());
	eraseInstFromBasicBlock(op_trunc_or_lshr, val.getParent());
	eraseInstFromBasicBlock(op_lshr, val.getParent());
	eraseInstFromBasicBlock(op_mul2, val.getParent());
	eraseInstFromBasicBlock(op_zext2, val.getParent());

	// value and modulo may have different types -> a conversion is needed
	// conversion can be from to smaller or even bigger
	if (val.getType() != mod->getType() && CastInst::castIsValid(Instruction::ZExt, mod, val.getType())) {
		val.getParent()->getInstList().insert(iter, mod);
		return CastInst::Create(Instruction::ZExt, mod, val.getType());
	} else if (val.getType() != mod->getType() && CastInst::castIsValid(Instruction::Trunc, mod, val.getType())) {
		val.getParent()->getInstList().insert(iter, mod);
		return CastInst::Create(Instruction::Trunc, mod, val.getType());
	} else
		return mod;
}

/**
 * Exchange
 *    -k * (x / 16 - (int32_t)(x < 0)) + x;
 * with x % k
 * This idiom is similar to magicSignedDiv7pos.
 *
 * @param iter value to visit
 * @return replaced Instruction, otherwise nullptr
 */
Instruction * IdiomsMagicDivMod::signedMod2(BasicBlock::iterator iter) const {
	/*
	 * Derivation tree (gcc-powerpc, signed % 29):
	 *
	 * There's only one "ashr", subtree is reused.
	 *                                                         add
	 *                                                          /\
	 *                                                    ------  ------
	 *                                                   /              \
	 *                                                  mul            <var>
	 *                                                  /\
	 *                                            ------  ------
	 *                                           /              \
	 *                                         sub            <magic>
	 *                                          /\
	 *                           ---------------  ---------------
	 *                          /                                \
	 *                        or                                 or
	 *                        /\                                 /\
	 *                  ------  ------                     ------  ------
	 *                 /              \                   /              \
	 *               and              lshr               and            lshr
	 *               /\                /\                /\              /\
	 *           ----  ----        ----  ----        ----  ----      ----  ----
	 *          /          \      /          \      /          \    /          \
	 *       *ashr       <mask> <var>        31  *ashr         -2 <var>      <shift>
	 *         /\
	 *     ----  ----
	 *    /          \
	 * <var>         31
	 *
	 */

	Instruction & val = (*iter);
	Value * op_add      = nullptr;
	Value * op_and1     = nullptr;
	Value * op_and2     = nullptr;
	Value * op_ashr     = nullptr;
	Value * op_ashr_tmp = nullptr;
	Value * op_lshr1    = nullptr;
	Value * op_lshr2    = nullptr;
	Value * op_mul      = nullptr;
	Value * op_or1      = nullptr;
	Value * op_or2      = nullptr;
	Value * op_sub      = nullptr;
	Value * op_var      = nullptr;
	ConstantInt * cnst  = nullptr;
	ConstantInt * k     = nullptr;

	if (! match(&val, m_Add(m_Value(op_mul), m_Value(op_var))))
		return nullptr;

	if (! match(op_mul, m_Mul(m_Value(op_sub), m_ConstantInt(k))))
		return nullptr;

	if (! match(op_sub, m_Sub(m_Value(op_or1), m_Value(op_or2))))
		return nullptr;

	// RHS of sub
	if (! match(op_or2, m_Or(m_Value(op_and1), m_Value(op_lshr1))))
		return nullptr;

	if (! match(op_lshr1, m_LShr(m_Value(op_var), m_ConstantInt(cnst))))
		return nullptr;

	if (! match(op_and1, m_And(m_Value(op_ashr), m_ConstantInt(cnst)))
			|| static_cast<signed>(*cnst->getValue().getRawData()) != -2)
		return nullptr;

	if (! match(op_ashr, m_AShr(m_Value(op_var), m_ConstantInt(cnst)))
			|| *cnst->getValue().getRawData() != 31)
		return nullptr;

	// LHS of sub
	if (! match(op_or1, m_Or(m_Value(op_and2), m_Value(op_lshr2))))
		return nullptr;

	// RHS of the left OR (or1)
	if (! match(op_lshr2, m_LShr(m_Value(op_var), m_ConstantInt(cnst))))
		return nullptr;

	// LHS of the left OR (or1)
	// Check only roots of subtrees, they will be reused, so we know what
	// instructions are in here...
	if (! match(op_and2, m_And(m_Value(op_ashr_tmp), m_ConstantInt(cnst))))
		return nullptr;

	if (op_ashr != op_ashr_tmp)
		return nullptr;

	// Replace it by "k". However, "k" might be negative, but it will be solved
	// by following pass "Combine redundant instructions".
	Constant *NewCst = ConstantInt::get(op_var->getType(), *k->getValue().getRawData());
	BinaryOperator *mod = BinaryOperator::CreateSRem(op_var, NewCst);

	eraseInstFromBasicBlock(op_add, val.getParent());
	eraseInstFromBasicBlock(op_and1, val.getParent());
	eraseInstFromBasicBlock(op_and2, val.getParent());
	eraseInstFromBasicBlock(op_ashr, val.getParent());
	eraseInstFromBasicBlock(op_lshr1, val.getParent());
	eraseInstFromBasicBlock(op_lshr2, val.getParent());
	eraseInstFromBasicBlock(op_mul, val.getParent());
	eraseInstFromBasicBlock(op_or1, val.getParent());
	eraseInstFromBasicBlock(op_or2, val.getParent());
	eraseInstFromBasicBlock(op_sub, val.getParent());

	return mod;
}

/**
 * Exchange
 *   x - x/k
 * with x % k
 *
 * @param iter value to visit
 * @return replaced Instruction, otherwise nullptr
 */
Instruction * IdiomsMagicDivMod::unsignedMod(BasicBlock::iterator iter) const {
	Instruction & val  = (*iter);
	Value * op_div     = nullptr;
	Value * op_var1    = nullptr;
	Value * op_var2    = nullptr;
	ConstantInt * cnst = nullptr;

	if (! match(&val, m_Sub(m_Value(op_var1), m_Value(op_div))))
		return nullptr;

	if (! match(op_div, m_UDiv(m_Value(op_var2), m_ConstantInt(cnst))))
		return nullptr;

	if (op_var2 != op_var1)
		return nullptr;

	eraseInstFromBasicBlock(op_div, val.getParent());

	BinaryOperator *urem = BinaryOperator::CreateURem(op_var1, cnst);

	return urem;
}

} // namespace bin2llvmir
} // namespace retdec

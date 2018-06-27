/**
 * @file src/bin2llvmir/optimizations/idioms/idioms_gcc.cpp
 * @brief GNU/GCC instruction idioms
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <cmath>

#include <llvm/IR/PatternMatch.h>
#include <llvm/Transforms/Utils/BasicBlockUtils.h>

#include "retdec/bin2llvmir/optimizations/idioms/idioms_gcc.h"
#include "retdec/bin2llvmir/utils/llvm.h"

using namespace llvm;
using namespace PatternMatch;

namespace retdec {
namespace bin2llvmir {

/**
 * Exchange (x ^ -2147483648) with -x
 *
 * @param iter value to visit
 * @return replaced Instruction, otherwise nullptr
 */
Instruction * IdiomsGCC::exchangeFloatNeg(BasicBlock::iterator iter) const {
	Instruction & val = (*iter);
	Value * op0 = nullptr;
	ConstantInt * cnst = nullptr;

	// (x ^ -2147483648) --> -x
	if (match(&val, m_Xor(m_Value(op0), m_ConstantInt(cnst)))
			|| match(&val, m_Xor(m_ConstantInt(cnst), m_Value(op0)))) {
		if (cnst->getBitWidth() == 32 && *cnst->getValue().getRawData() == -0x80000000) {
			return BinaryOperator::CreateNeg(op0);
		}
	}

	return nullptr;
}

/**
 * Exchange x ^ -1 with -x - 1
 *
 * @param iter value to visit
 * @return replaced Instruction, otherwise nullptr
 */
Instruction * IdiomsGCC::exchangeXorMinusOne(BasicBlock::iterator iter) const {
	Instruction & val = (*iter);
	Value * op0 = nullptr;
	ConstantInt * cnst = nullptr;

	// x ^ -1 --> -x - 1
	if ((match(&val, m_Xor(m_Value(op0), m_ConstantInt(cnst)))
				|| match(&val, m_Xor(m_ConstantInt(cnst), m_Value(op0))))
			&& cnst->isMinusOne()) {

		Constant *NewCst = ConstantInt::get(op0->getType(), 1);

		Instruction * neg = BinaryOperator::CreateNeg(op0);
		val.getParent()->getInstList().insert(iter, neg);

		return BinaryOperator::CreateSub(neg, NewCst);
	}

	return nullptr;
}

/**
 * Exchange (((lshr(X, 31) + X) & 1) - lshr(X, 31))) with X % 2
 *
 * @param iter value to visit
 * @return replaced Instruction, otherwise nullptr
 */
Instruction * IdiomsGCC::exchangeSignedModuloByTwo(BasicBlock::iterator iter) const {
	Instruction & val = (*iter);
	Value * op_and = nullptr;
	Value * op_lshr = nullptr;
	Value * op_lshr2 = nullptr;
	Value * op_add = nullptr;
	Value * op_x = nullptr;
	Value * op_x_tmp = nullptr;
	ConstantInt * cnst = nullptr;

	// (((lshr(X, 31) + X) & 1) - lshr(X, 31)) --> X % 2
	if (! match(&val, m_Sub(m_Value(op_and), m_Value(op_lshr))))
		return nullptr;

	if (! match(op_lshr, m_LShr(m_Value(op_x), m_ConstantInt(cnst)))
			|| *cnst->getValue().getRawData() != 31)
		return nullptr;

	if (! match(op_and, m_And(m_Value(op_add), m_ConstantInt(cnst)))
			&& ! match(op_and, m_And(m_ConstantInt(cnst), m_Value(op_add))))
		return nullptr;

	if (! cnst->isOne())
		return nullptr;

	if (! match(op_add, m_Add(m_Value(op_lshr2), m_Value(op_x_tmp))))
		return nullptr;

	// are we still using X? add is commutative
	if (op_x_tmp != op_x) {
		if (op_lshr2 == op_x) {
			// op_lshr2 was checked for X, now it can be discarded
			op_lshr2 = op_x_tmp;
		} else
			return nullptr;
	}

	if (! match(op_lshr2, m_LShr(m_Value(op_x_tmp), m_ConstantInt(cnst)))
			|| *cnst->getValue().getRawData() != 31)
		return nullptr;

	if (op_x_tmp != op_x)
		return nullptr;

	// now exchange the idiom
	eraseInstFromBasicBlock(op_lshr, val.getParent());
	eraseInstFromBasicBlock(op_lshr2, val.getParent());
	eraseInstFromBasicBlock(op_add, val.getParent());
	eraseInstFromBasicBlock(op_and, val.getParent());

	Constant *NewCst = ConstantInt::get(op_x->getType(), 2);
	return BinaryOperator::CreateSRem(op_x, NewCst);
}

/**
 * Exchange (X < 0 ? X + (N-1) : X) a>> log2(N) with X s/ N
 *
 * @param iter value to visit
 * @return replaced Instruction, otherwise nullptr
 */
Instruction * IdiomsGCC::exchangeCondBitShiftDiv1(BasicBlock::iterator iter) const {
	Instruction & val = (*iter);
	Value * op_add = nullptr;
	Value * op_var = nullptr;
	Value * op_select = nullptr;
	Value * op_cmp = nullptr;
	ConstantInt * cnst = nullptr;
	ICmpInst::Predicate pred;

	// (X < 0 ? X + (N-1) : X) a>> log2(N) --> X s/ N
	if (! match(&val, m_AShr(m_Value(op_select), m_ConstantInt(cnst))))
		return nullptr;

	if (! match(op_select, m_Select(m_Value(op_cmp), m_Value(op_add), m_Value(op_var))))
		return nullptr;

	if (! match(op_cmp, m_ICmp(pred, m_Value(op_var), m_ConstantInt(cnst)))
			|| *cnst->getValue().getRawData() != 0)
		return nullptr;

	if (pred != ICmpInst::ICMP_SLT)
		return nullptr;

	if (! match(op_add, m_Add(m_Value(op_var), m_ConstantInt(cnst)))
			&& ! match(op_add, m_Add(m_ConstantInt(cnst), m_Value(op_var))))
		return nullptr;

	if (! isPowerOfTwoRepresentable(cnst))
		return nullptr;

	// now exchange the idiom
	eraseInstFromBasicBlock(op_add, val.getParent());
	eraseInstFromBasicBlock(op_select, val.getParent());
	eraseInstFromBasicBlock(op_cmp, val.getParent());

	unsigned shift = *cnst->getValue().getRawData();
	Constant *NewCst = ConstantInt::get(val.getType(), pow(2, shift));
	return BinaryOperator::CreateSDiv(op_var, NewCst);
}

/**
 * Division by negative power of two. Found on PowerPC, e.g. div -4.
 * Exchange 0 - ((X >> shift) | ((X >> 31) & mask))
 *
 * @param iter value to visit
 * @return replaced Instruction, otherwise nullptr
 */
Instruction * IdiomsGCC::exchangeCondBitShiftDiv2(BasicBlock::iterator iter) const {
	Instruction & val = (*iter);
	Value * op_var = nullptr;
	Value * op_or = nullptr;
	Value * op_and = nullptr;
	Value * op_lshr = nullptr;
	Value * op_ashr = nullptr;
	ConstantInt * cnst = nullptr;

	if (! match(&val, m_Sub(m_ConstantInt(cnst), m_Value(op_or)))
			|| *cnst->getValue().getRawData() != 0)
		return nullptr;

	if (! match(op_or, m_Or(m_Value(op_and), m_Value(op_lshr))))
		return nullptr;

	if (! match(op_and, m_And(m_Value(op_ashr), m_ConstantInt(cnst))))
		return nullptr;

	if (! match(op_ashr, m_AShr(m_Value(op_var), m_ConstantInt(cnst)))
			|| *cnst->getValue().getRawData() != 31)
		return nullptr;

	if (! match(op_lshr, m_LShr(m_Value(op_var), m_ConstantInt(cnst))))
		return nullptr;

	if (! isPowerOfTwoRepresentable(cnst))
		return nullptr;

	// now exchange the idiom
	eraseInstFromBasicBlock(op_ashr, val.getParent());
	eraseInstFromBasicBlock(op_and, val.getParent());
	eraseInstFromBasicBlock(op_lshr, val.getParent());
	eraseInstFromBasicBlock(op_or, val.getParent());

	unsigned shift = *cnst->getValue().getRawData();
	Constant *NewCst = ConstantInt::get(val.getType(), -pow(2, shift));
	return BinaryOperator::CreateSDiv(op_var, NewCst);
}

/**
 * Division by negative power of two. Found on PowerPC, e.g. div -2.
 * Exchange 0 - ((X >> shift) | (X & mask)) -- in case of div -2.
 *
 * @param iter value to visit
 * @return replaced Instruction, otherwise nullptr
 */
Instruction * IdiomsGCC::exchangeCondBitShiftDiv3(BasicBlock::iterator iter) const {
	Instruction & val = (*iter);
	Value * op_var = nullptr;
	Value * op_or = nullptr;
	Value * op_and = nullptr;
	Value * op_lshr = nullptr;
	ConstantInt * cnst = nullptr;

	if (! match(&val, m_Sub(m_ConstantInt(cnst), m_Value(op_or)))
			|| *cnst->getValue().getRawData() != 0)
		return nullptr;

	if (! match(op_or, m_Or(m_Value(op_lshr), m_Value(op_and))))
		return nullptr;

	if (! match(op_and, m_And(m_Value(op_var), m_ConstantInt(cnst))))
		return nullptr;

	if (! match(op_lshr, m_LShr(m_Value(op_var), m_ConstantInt(cnst))))
		return nullptr;

	if (! isPowerOfTwoRepresentable(cnst))
		return nullptr;

	// now exchange the idiom
	eraseInstFromBasicBlock(op_and, val.getParent());
	eraseInstFromBasicBlock(op_lshr, val.getParent());
	eraseInstFromBasicBlock(op_or, val.getParent());

	unsigned shift = *cnst->getValue().getRawData();
	Constant *NewCst = ConstantInt::get(val.getType(), -pow(2, shift));
	return BinaryOperator::CreateSDiv(op_var, NewCst);
}

/**
 * Exchange X & 0x7FFFFFFF with fabsf(X)
 *
 * @param iter value to visit
 * @return replaced Instruction, otherwise nullptr
 */
Instruction * IdiomsGCC::exchangeFloatAbs(BasicBlock::iterator iter) const {
	Instruction & val = (*iter);
	Module * M = getModule();
	LLVMContext & Context = M->getContext();
	const DataLayout & dl = M->getDataLayout();
	ConstantInt * cnst = nullptr;
	Value * op_x = nullptr;

	// X & 0x7FFFFFFF --> fabsf(X)
	if (! match(&val, m_And(m_Value(op_x), m_ConstantInt(cnst)))
			&& ! match(&val, m_And(m_ConstantInt(cnst), m_Value(op_x))))
		return nullptr;

	if (*cnst->getValue().getRawData() != 0x7FFFFFFF)
		return nullptr;

	auto* fun = llvm::Intrinsic::getDeclaration(
			M,
			llvm::Intrinsic::fabs,
			Type::getFloatTy(Context));

	// Arguments have to be casted to float
	if (dl.getTypeSizeInBits(op_x->getType()) != dl.getTypeSizeInBits(Type::getFloatTy(Context)))
		return nullptr;
	Instruction * x_cast = CastInst::Create(Instruction::BitCast, op_x, Type::getFloatTy(Context));

	// call the function
	Value * args[] = { x_cast };
	CallInst * call = CallInst::Create(fun, args);

	Instruction * ret_cast = CastInst::Create(Instruction::BitCast, call, Type::getInt32Ty(Context));

	// insert in reverse order
	val.getParent()->getInstList().insert(iter, x_cast);
	val.getParent()->getInstList().insert(iter, call);

	return ret_cast;
}

/**
 * Exchange multi BB idiom, found only when compiling for ARM with -Os.
 *
 * @param f function to visit
 * @param pass actual pass
 * @return idioms replaced
 */
int IdiomsGCC::exchangeCondBitShiftDivMultiBB(Function & f, Pass * pass) const {
	/**
	 * res = n % 2:
	 *   dec_label:
	 *     %u12 = and i32 %n, -2147483647
	 *     %u13 = icmp slt i32 %u12, 0
	 *     %u11 = sext i1 %u13 to i32
	 *     %u11.u12 = add i32 %u11, %u12
	 *     br i1 %u13, label %if_true, label %after_if
	 *
	 *   if_true:
	 *     %fold = add i32 %u11, %n
	 *     %u5 = or i32 %fold, -2
	 *     %u11 = add i32 %u5, 1
	 *     br label %after_if
	 *
	 *   after_if_8230_3:
	 *     %res = phi i32 [ %u11, %if_true ], [ %u11.u12, %dec_label ]
	 *
	 * This idiom was found when compiling for ARM with -Os (GCC)
	 *
	 * Multi BB idiom. Before branch:
	 *
	 *                                     icmp slt
	 *                                        /\
	 *                                 -------  -------
	 *                                /                \
	 *                              and                 0
	 *                              /\
	 *                       -------  -------
	 *                      /                \
	 *                    <n>           -2147483647
	 *
	 *
	 * if icmp is true (if_true block)
	 *
	 *                                        add
	 *                                        /\
	 *                                 -------  -------
	 *                                /                \
	 *                              or                  1
	 *                              /\
	 *                       -------  -------
	 *                      /                \
	 *                    add                 -2
	 *                     /\
	 *              -------  -------
	 *             /                \
	 *           <n>                 1
	 *
	 */
	Value * op_icmp      = nullptr;
	Value * op_and       = nullptr;
	Value * op_n         = nullptr;
	ConstantInt * cnst   = nullptr;
	ICmpInst::Predicate pred;
	BasicBlock * if_true_bb = nullptr;
	int num_idioms = 0;

	BranchInst * br = nullptr;

	for (Function::iterator bb = f.begin(); bb != f.end(); ++bb) {
		for (BasicBlock::iterator i = (*bb).begin(); i != (*bb).end(); ++i) {
			// there can be mutliple idioms, if found some, clear pointer to bb with if
			if_true_bb = nullptr;
			BasicBlock::iterator j = i;
			op_icmp = &cast<Value>(*j);

			if ((! match(op_icmp, m_ICmp(pred, m_Value(op_and), m_ConstantInt(cnst)))
						&& ! match(op_icmp, m_ICmp(pred, m_ConstantInt(cnst), m_Value(op_and))))
					|| *cnst->getValue().getRawData() != 0
					|| pred != ICmpInst::ICMP_SLT)
				continue;

			if ((! match(op_and, m_And(m_Value(op_n), m_ConstantInt(cnst)))
						&& ! match(op_and, m_And(m_ConstantInt(cnst), m_Value(op_n))))
					|| *cnst->getValue().getRawData() != 0x80000001)
				continue;

			if (findBranchDependingOn(&br, *bb, op_icmp)) {
				Value * op_add         = nullptr;
				Value * op_or          = nullptr;
				Value * op_add2        = nullptr;
				Value * op_v1          = nullptr;
				Value * op_v2          = nullptr;

				// now find if_true BB
				bool end = false;
				for (Function::iterator m = f.begin(); m != f.end() && ! end; ++m) {
					// inspect only BB which is referenced by branch
					if (br->isConditional() && br->getSuccessor(0) == &(*m)) {
						for (BasicBlock::iterator k = (*m).begin(); k != (*m).end() && ! end; ++k){
							op_add = &cast<Value>(*k);

							if (! match(op_add, m_Add(m_Value(op_or), m_ConstantInt(cnst)))
									&& ! match(op_add, m_Add(m_ConstantInt(cnst), m_Value(op_or))))
								continue;

							if (static_cast<int32_t>(*cnst->getValue().getRawData()) != 1)
								continue;

							if (! match(op_or, m_Or(m_Value(op_add2), m_ConstantInt(cnst)))
									&& ! match(op_or, m_Or(m_ConstantInt(cnst), m_Value(op_add2))))
								continue;

							if (static_cast<int32_t>(*cnst->getValue().getRawData()) != -2)
								continue;

							if (! match(op_add2, m_Add(m_Value(op_v1), m_Value(op_v2))))
								continue;

							if (op_v1 != op_n && op_v2 != op_n)
								continue;

							if_true_bb = &(*m);

							eraseInstFromBasicBlock(op_add,  if_true_bb);
							eraseInstFromBasicBlock(op_or,   if_true_bb);
							eraseInstFromBasicBlock(op_add2, if_true_bb);

							end = true;
						}
					}
				}

				// we have to find PHI node which uses if_true BB, look for it only
				// if if_true_bb was found
				for (Function::iterator target_bb = f.begin(); if_true_bb && target_bb != f.end(); ++target_bb) {
					for (BasicBlock::iterator m = (*target_bb).begin(); m != (*target_bb).end(); ++m) {
						if (PHINode * phi = dyn_cast<PHINode>(&(*m))) {
							// find phi node referencing if_true
							if (*(phi->block_begin()) == if_true_bb) {
								// new insn
								Constant *NewCst = ConstantInt::get(op_n->getType(), 2);
								Instruction * srem = BinaryOperator::Create(Instruction::SRem, op_n, NewCst);
								// take care, this is PHI, not common insn
								phi->replaceAllUsesWith(srem);
								srem->takeName(phi);
								// insert point is first insn, not the PHI
								BasicBlock::iterator iter = phi->getParent()->getFirstInsertionPt();
								phi->getParent()->getInstList().insert(iter, srem);
								phi->eraseFromParent();
								num_idioms++;

								// op_n is use of srem, do not erase it!
								eraseInstFromBasicBlock(op_icmp,   &(*bb));
								eraseInstFromBasicBlock(op_and,    &(*bb));

								return num_idioms;
							}
						}
					}
				}
			}
		}
	}

	return num_idioms;
}

/**
 * Exchange X = ((A & 0x7FFFFFFF) | (B & 0x80000000)) with copysignf(A, B)
 * or X = ((fabsf(A)) | (B & 0x80000000)) with copysignf(A, B)
 *
 * @param iter value to visit
 * @return replaced Instruction, otherwise nullptr
 */
Instruction * IdiomsGCC::exchangeCopysign(BasicBlock::iterator iter) const {
	Instruction & val = (*iter);
	Module * M = getModule();
	LLVMContext & Context = M->getContext();
	Value * op_and1 = nullptr;
	Value * op_and2 = nullptr;
	Value * op_a = nullptr;
	Value * op_b = nullptr;
	ConstantInt * cnst1 = nullptr;
	ConstantInt * cnst2 = nullptr;

	// X = ((A & 0x7FFFFFFF) | (B & 0x80000000)) --> copysignf(A, B)
	if (! match(&val, m_Or(m_Value(op_and1), m_Value(op_and2))))
		return nullptr;

	// left hand side of or is (A & 0x7FFFFFFF)?
	if (! match(op_and1, m_And(m_Value(op_a), m_ConstantInt(cnst1)))
			&& ! match(op_and1, m_And(m_ConstantInt(cnst1), m_Value(op_a))))
	{
		// left hand side of or is (fabsf(A)?
		op_and1 = llvm_utils::skipCasts(op_and1);
		if (isa<CallInst>(op_and1)
				&& cast<CallInst>(op_and1)->getCalledFunction()
				&& cast<CallInst>(op_and1)->getCalledFunction()->getIntrinsicID() == Intrinsic::fabs)
		{
			auto* call = cast<CallInst>(op_and1);
			op_a = call->getArgOperand(0);
			cnst1 = cast<ConstantInt>(ConstantInt::get(op_and2->getType(), 0x7FFFFFFF));
		}
		else
		{
			return nullptr;
		}
	}

	unsigned second_cnst; // or is commutative, mark next constant
	if (*cnst1->getValue().getRawData() != 0x7FFFFFFF) {
		if (*cnst1->getValue().getRawData() != 0x80000000)
			return nullptr;
		else
			second_cnst = 0x7FFFFFFF;
	} else {
		second_cnst = 0x80000000;
	}

	// right hand side of or
	if (! match(op_and2, m_And(m_Value(op_b), m_ConstantInt(cnst2)))
			&& ! match(op_and2, m_And(m_ConstantInt(cnst2), m_Value(op_b))))
		return nullptr;

	if (*cnst2->getValue().getRawData() != second_cnst)
		return nullptr;

	auto* fun = llvm::Intrinsic::getDeclaration(
			M,
			llvm::Intrinsic::copysign,
			Type::getFloatTy(Context));

	// Arguments have to be casted to float

	Instruction * a_cast = nullptr;
	if (op_a->getType()->isFloatTy())
	{
		a_cast = cast<Instruction>(op_a);
	}
	else if (op_a->getType()->isIntegerTy(32))
	{
		a_cast = CastInst::Create(Instruction::BitCast, op_a, Type::getFloatTy(Context));
	}
	else
	{
		return nullptr;
	}
	Instruction * b_cast = CastInst::Create(Instruction::BitCast, op_b, Type::getFloatTy(Context));

	// call the function
	Value * args[2];

	// arguments depends on constants used
	if (second_cnst == 0x80000000) {
		args[0] = a_cast;
		args[1] = b_cast;
	} else {
		args[1] = a_cast;
		args[0] = b_cast;
	}

	CallInst * call = CallInst::Create(fun, args);

	Instruction * ret_cast = CastInst::Create(Instruction::BitCast, call, Type::getInt32Ty(Context));

	// erase substituted idiom
	eraseInstFromBasicBlock(op_and1, val.getParent());
	eraseInstFromBasicBlock(op_and2, val.getParent());

	// insert in reverse order
	val.getParent()->getInstList().insert(iter, b_cast);
	if (a_cast != op_a)
	{
		val.getParent()->getInstList().insert(iter, a_cast);
	}
	val.getParent()->getInstList().insert(iter, call);

	return ret_cast;
}

} // namespace bin2llvmir
} // namespace retdec

/**
 * @file src/bin2llvmir/optimizations/inst_opt/inst_opt.cpp
 * @brief Optimize a single LLVM instruction.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <llvm/IR/PatternMatch.h>

#include "retdec/bin2llvmir/optimizations/inst_opt/inst_opt.h"

using namespace llvm;
using namespace PatternMatch;

namespace retdec {
namespace bin2llvmir {
namespace inst_opt {

/**
 * x = add y, 0
 *   =>
 * x = y
 *
 * x = add 0, y
 *   =>
 * x = y
 */
bool addZero(llvm::Instruction* insn)
{
	Value* val;
	uint64_t zero;

	if (!(match(insn, m_Add(m_Value(val), m_ConstantInt(zero)))
			|| match(insn, m_Add(m_ConstantInt(zero), m_Value(val)))))
	{
		return false;
	}
	if (zero != 0)
	{
		return false;
	}

	insn->replaceAllUsesWith(val);
	insn->eraseFromParent();
	return true;
}

/**
 * x = sub y, 0
 *   =>
 * x = use y
 */
bool subZero(llvm::Instruction* insn)
{
	uint64_t zero;

	if (!match(insn, m_Sub(m_Value(), m_ConstantInt(zero))))
	{
		return false;
	}
	if (zero != 0)
	{
		return false;
	}

	insn->replaceAllUsesWith(insn->getOperand(0));
	insn->eraseFromParent();
	return true;
}

/**
 * a = trunc i32 val to i8
 * b = zext i8 a to i32
 *   =>
 * b = and i32 val, 255
 *
 * a = trunc i32 val to i16
 * b = zext i16 a to i32
 *   =>
 * b = and i32 val, 65535
 */
bool truncZext(llvm::Instruction* insn)
{
	Value* val;

	if (!match(insn, m_ZExt(m_Trunc(m_Value(val)))))
	{
		return false;
	}
	auto* zext = cast<ZExtInst>(insn);
	auto* trunc = cast<TruncInst>(zext->getOperand(0));
	Instruction* a = nullptr;

	if (trunc->getSrcTy()->isIntegerTy(32)
		&& trunc->getDestTy()->isIntegerTy(8)
		&& zext->getSrcTy()->isIntegerTy(8)
		&& zext->getDestTy()->isIntegerTy(32))
	{
		a = BinaryOperator::CreateAnd(
				val,
				ConstantInt::get(val->getType(), 255),
				"",
				zext);
	}
	else if (trunc->getSrcTy()->isIntegerTy(32)
			&& trunc->getDestTy()->isIntegerTy(16)
			&& zext->getSrcTy()->isIntegerTy(16)
			&& zext->getDestTy()->isIntegerTy(32))
	{
		a = BinaryOperator::CreateAnd(
				val,
				ConstantInt::get(val->getType(), 65535),
				"",
				zext);
	}
	if (a == nullptr)
	{
		return false;
	}

	a->takeName(zext);
	zext->replaceAllUsesWith(a);
	zext->eraseFromParent();
	if (trunc->user_empty())
	{
		trunc->eraseFromParent();
	}

	return true;
}

/**
 * a = xor x, x
 *   =>
 * a = 0
 */
bool xorXX(llvm::Instruction* insn)
{
	Value* op0;
	Value* op1;

	if (!(match(insn, m_Xor(m_Value(op0), m_Value(op1)))
			&& op0 == op1))
	{
		return false;
	}

	insn->replaceAllUsesWith(ConstantInt::get(insn->getType(), 0));
	insn->eraseFromParent();

	return true;
}

/**
 * a = load x
 * b = load x
 * c = xor a, b
 *   =>
 * c = 0
 */
bool xorLoadXX(llvm::Instruction* insn)
{
	Instruction* i1;
	Instruction* i2;

	if (!(match(insn, m_Xor(m_Instruction(i1), m_Instruction(i2)))
			&& isa<LoadInst>(i1)
			&& isa<LoadInst>(i2)))
	{
		return false;
	}
	LoadInst* l1 = cast<LoadInst>(i1);
	LoadInst* l2 = cast<LoadInst>(i2);
	if (l1->getPointerOperand() != l2->getPointerOperand())
	{
		return false;
	}

	insn->replaceAllUsesWith(ConstantInt::get(insn->getType(), 0));
	insn->eraseFromParent();
	if (l1->user_empty())
	{
		l1->eraseFromParent();
	}
	if (l2 != l1 && l2->user_empty())
	{
		l2->eraseFromParent();
	}

	return true;
}

/**
 * a = or x, x
 *   =>
 * a = x
 *
 * a = and x, x
 *   =>
 * a = x
 */
bool orAndXX(llvm::Instruction* insn)
{
	Value* op0;
	Value* op1;

	if (!(match(insn, m_Or(m_Value(op0), m_Value(op1)))
			|| match(insn, m_And(m_Value(op0), m_Value(op1)))))
	{
		return false;
	}
	if (op0 != op1)
	{
		return false;
	}

	insn->replaceAllUsesWith(op0);
	insn->eraseFromParent();

	return true;
}

/**
 * a = load x
 * b = load x
 * c = or a, b
 *   =>
 * c = 0
 *
 * a = load x
 * b = load x
 * c = and a, b
 *   =>
 * c = 0
 */
bool orAndLoadXX(llvm::Instruction* insn)
{
	Instruction* i1;
	Instruction* i2;

	if (!(match(insn, m_Or(m_Instruction(i1), m_Instruction(i2)))
			|| match(insn, m_And(m_Instruction(i1), m_Instruction(i2)))))
	{
		return false;
	}
	LoadInst* l1 = dyn_cast<LoadInst>(i1);
	LoadInst* l2 = dyn_cast<LoadInst>(i2);
	if (l1 == nullptr
			|| l2 == nullptr
			|| l1->getPointerOperand() != l2->getPointerOperand())
	{
		return false;
	}

	insn->replaceAllUsesWith(l1);
	insn->eraseFromParent();
	if (l2->user_empty())
	{
		l2->eraseFromParent();
	}

	return true;
}

/**
 * a = xor i1 x, y
 *   =>
 * a = icmp ne i1 x, y
 */
bool xor_i1(llvm::Instruction* insn)
{
	Value* op0;
	Value* op1;

	if (!(match(insn, m_Xor(m_Value(op0), m_Value(op1)))
			&& insn->getType()->isIntegerTy(1)))
	{
		return false;
	}

	auto* cmp = CmpInst::Create(
			Instruction::ICmp,
			ICmpInst::ICMP_NE,
			op0,
			op1,
			"",
			insn);
	cmp->takeName(insn);
	insn->replaceAllUsesWith(cmp);
	insn->eraseFromParent();

	return true;
}

/**
 * a = and i1 x, y
 *   =>
 * a = icmp eq i1 x, y
 */
bool and_i1(llvm::Instruction* insn)
{
	Value* op0;
	Value* op1;

	if (!(match(insn, m_And(m_Value(op0), m_Value(op1)))
			&& insn->getType()->isIntegerTy(1)))
	{
		return false;
	}

	auto* cmp = CmpInst::Create(
			Instruction::ICmp,
			ICmpInst::ICMP_EQ,
			op0,
			op1,
			"",
			insn);
	cmp->takeName(insn);
	insn->replaceAllUsesWith(cmp);
	insn->eraseFromParent();

	return true;
}

/**
 * a = add x, c1
 * b = add a, c2
 *   =>
 * b = add x, (c1 + c2)
 */
bool addSequence(llvm::Instruction* insn)
{
	Value* val;
	ConstantInt* c1;
	ConstantInt* c2;

	if (!(match(insn, m_Add(
			m_Add(m_Value(val), m_ConstantInt(c1)),
			m_ConstantInt(c2)))))
	{
		return false;
	}

	Instruction* secondAdd = cast<Instruction>(insn->getOperand(0));
	insn->setOperand(0, val);
	insn->setOperand(1, ConstantInt::get(insn->getType(), c1->getValue() + c2->getValue()));

	if (secondAdd->user_empty())
	{
		secondAdd->eraseFromParent();
	}

	return true;
}

/**
 * cast1 int/fp/ptr to ...
 * ...
 * cast2 ... to int/fp/ptr
 *   =>
 * cast int/fp/ptr to int/fp/ptr
 */
llvm::Value* castSequence(llvm::CastInst* cast1, llvm::CastInst* cast2)
{
	auto* src = cast1->getOperand(0);
	auto* srcTy = cast1->getSrcTy();
	auto* dstTy = cast2->getDestTy();

	Value* v = nullptr;

	// int -> cast -> cast -> int
	if (srcTy->isIntegerTy() && dstTy->isIntegerTy())
	{
		bool sign = cast1->getOpcode() == Instruction::SIToFP
				|| cast2->getOpcode() == Instruction::FPToSI;
		v = srcTy != dstTy
				? CastInst::CreateIntegerCast(src, dstTy, sign, "", cast2)
				: src;
	}
	// ptr -> cast -> cast -> ptr
	else if (srcTy->isPointerTy() && dstTy->isPointerTy())
	{
		v = srcTy != dstTy
				? CastInst::CreatePointerCast(src, dstTy, "", cast2)
				: src;
	}
	// float -> cast -> cast -> float
	else if (srcTy->isFloatingPointTy() && dstTy->isFloatingPointTy())
	{
		v = srcTy != dstTy
				? CastInst::CreateFPCast(src, dstTy, "", cast2)
				: src;
	}
	else
	{
		return nullptr;
	}

	cast2->replaceAllUsesWith(v);
	cast2->eraseFromParent();
	if (cast1->user_empty())
	{
		cast1->eraseFromParent();
	}
	return v;
}

/**
 * Find cast sequnces to try to optimize.
 */
llvm::Value* castSequenceFinder(llvm::Value* insn)
{
	auto* cast2 = dyn_cast<CastInst>(insn);
	auto* cast1 = cast2 ? dyn_cast<CastInst>(cast2->getOperand(0)) : nullptr;

	while (cast1)
	{
		if (auto* v = castSequence(cast1, cast2))
		{
			return v;
		}
		cast1 = dyn_cast<CastInst>(cast1->getOperand(0));
	}

	return nullptr;
}

/**
 * Apply cast optimization repeatedly until it can not be applied anymore.
 */
bool castSequenceWrapper(llvm::Instruction* insn)
{
	bool changed = false;
	Value* v = insn;
	while (v)
	{
		v = castSequenceFinder(v);
		changed |= v != nullptr;
	}
	return changed;
}

/**
 * Order here is important.
 * More specific patterns must go first, more general later.
 */
std::vector<bool (*)(llvm::Instruction*)> optimizations =
{
		&addZero,
		&subZero,
		&truncZext,
		&xorLoadXX,
		&xorXX,
		&xor_i1,
		&and_i1,
		&orAndLoadXX,
		&orAndXX,
		&addSequence,
		&castSequenceWrapper,
};

bool optimize(llvm::Instruction* insn)
{
	for (auto& f : optimizations)
	{
		if (f(insn))
		{
			return true;
		}
	}
	return false;
}

} // namespace inst_opt
} // namespace bin2llvmir
} // namespace retdec

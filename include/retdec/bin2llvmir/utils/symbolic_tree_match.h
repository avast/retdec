/**
 * @file include/retdec/bin2llvmir/utils/ir_modifier.h
 * @brief Pattern matching for @c SymbolicTree.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 *
 * Simple and efficient mechanism for performing general tree-based
 * pattern matches on the @c SymbolicTree structures.
 *
 * Inspired by LLVM's IR/PatternMatch.h.
 */

#ifndef RETDEC_BIN2LLVMIR_UTILS_SYMBOLIC_TREE_MATCH_H
#define RETDEC_BIN2LLVMIR_UTILS_SYMBOLIC_TREE_MATCH_H

#include "retdec/bin2llvmir/analyses/symbolic_tree.h"

namespace retdec {
namespace bin2llvmir {
namespace st_match {

//
//==============================================================================
// Main matching function.
//==============================================================================
//

template <typename Pattern>
bool match(SymbolicTree& st, const Pattern& p)
{
    return const_cast<Pattern&>(p).match(st);
}

//
//==============================================================================
// Matching combinators.
//==============================================================================
//

template<typename LTy, typename RTy> struct match_combine_or
{
	LTy L;
	RTy R;

	match_combine_or(const LTy &Left, const RTy &Right) :
			L(Left), R(Right)
	{
	}

	bool match(SymbolicTree& V)
	{
		if (L.match(V))
			return true;
		if (R.match(V))
			return true;
		return false;
	}
};

template<typename LTy, typename RTy> struct match_combine_and
{
	LTy L;
	RTy R;

	match_combine_and(const LTy &Left, const RTy &Right) :
			L(Left), R(Right)
	{
	}

	bool match(SymbolicTree& V)
	{
		if (L.match(V))
			if (R.match(V))
				return true;
		return false;
	}
};

/// Combine two pattern matchers matching L || R
template<typename LTy, typename RTy>
inline match_combine_or<LTy, RTy> m_CombineOr(const LTy &L, const RTy &R)
{
	return match_combine_or<LTy, RTy>(L, R);
}

/// Combine two pattern matchers matching L && R
template<typename LTy, typename RTy>
inline match_combine_and<LTy, RTy> m_CombineAnd(const LTy &L, const RTy &R)
{
	return match_combine_and<LTy, RTy>(L, R);
}

//
//==============================================================================
// Any Binary matcher.
//==============================================================================
//

template <typename LHS_t, typename RHS_t, bool Commutable = false>
struct AnyBinaryOp_match
{
	LHS_t L;
	RHS_t R;
	llvm::BinaryOperator** insn = nullptr;

	AnyBinaryOp_match(const LHS_t &LHS, const RHS_t &RHS, llvm::BinaryOperator** i) :
			L(LHS),
			R(RHS),
			insn(i)
	{
	}

	bool match(SymbolicTree& st)
	{
        if (!st.isBinary())
        {
            return false;
        }

		if (auto* I = llvm::dyn_cast<llvm::BinaryOperator>(st.value))
		{
			if ((L.match(st.ops[0]) && R.match(st.ops[1]))
            		|| (Commutable && L.match(st.ops[1]) && R.match(st.ops[0])))
            {
				if (insn)
				{
					*insn = I;
				}
				return true;
            }
		}

		return false;
	}
};

template <typename LHS, typename RHS>
inline AnyBinaryOp_match<LHS, RHS> m_BinOp(
		const LHS &L,
		const RHS &R,
		llvm::BinaryOperator** insn = nullptr)
{
	return AnyBinaryOp_match<LHS, RHS>(L, R, insn);
}

template <typename LHS, typename RHS>
inline AnyBinaryOp_match<LHS, RHS, true> m_c_BinOp(
		const LHS &L,
		const RHS &R,
		llvm::BinaryOperator** insn = nullptr)
{
	return AnyBinaryOp_match<LHS, RHS, true>(L, R, insn);
}

//
//==============================================================================
// Binary matcher.
//==============================================================================
//

template <typename LHS_t, typename RHS_t, unsigned Opcode, bool Commutable = false>
struct BinaryOp_match
{
    LHS_t L;
    RHS_t R;
    llvm::Instruction** insn = nullptr;

    BinaryOp_match(const LHS_t &LHS, const RHS_t &RHS, llvm::Instruction** i = nullptr) :
            L(LHS),
            R(RHS),
			insn(i)
    {
    }

    bool match(SymbolicTree& st)
    {
        if (!st.isBinary())
        {
            return false;
        }

        if (st.value->getValueID() == llvm::Value::InstructionVal + Opcode)
        {
            if ((L.match(st.ops[0]) && R.match(st.ops[1]))
            		|| (Commutable && L.match(st.ops[1]) && R.match(st.ops[0])))
            {
            	if (insn)
            	{
            		*insn = llvm::cast<llvm::Instruction>(st.value);
            	}
            	return true;
            }
        }
        if (auto* ce = llvm::dyn_cast<llvm::ConstantExpr>(st.value))
        {
            return ce->getOpcode() == Opcode &&
            		((L.match(st.ops[0]) && R.match(st.ops[1]))
					|| (Commutable && L.match(st.ops[1]) && R.match(st.ops[0])));
        }

        return false;
    }
};

//
//==============================================================================
// Binary matchers - non-commutative.
//==============================================================================
//

template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, llvm::Instruction::Add> m_Add(
		const LHS &L,
		const RHS &R,
		llvm::Instruction** add = nullptr)
{
	return BinaryOp_match<LHS, RHS, llvm::Instruction::Add>(L, R, add);
}

template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, llvm::Instruction::FAdd> m_FAdd(
	const LHS &L,
	const RHS &R,
	llvm::Instruction** fadd = nullptr)
{
	return BinaryOp_match<LHS, RHS, llvm::Instruction::FAdd>(L, R, fadd);
}

template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, llvm::Instruction::Sub> m_Sub(
		const LHS &L,
		const RHS &R,
		llvm::Instruction** sub = nullptr)
{
	return BinaryOp_match<LHS, RHS, llvm::Instruction::Sub>(L, R, sub);
}

template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, llvm::Instruction::FSub> m_FSub(
		const LHS &L,
		const RHS &R,
		llvm::Instruction** fsub = nullptr)
{
	return BinaryOp_match<LHS, RHS, llvm::Instruction::FSub>(L, R, fsub);
}

template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, llvm::Instruction::Mul> m_Mul(
		const LHS &L,
		const RHS &R,
		llvm::Instruction** mul = nullptr)
{
	return BinaryOp_match<LHS, RHS, llvm::Instruction::Mul>(L, R, mul);
}

template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, llvm::Instruction::FMul> m_FMul(
		const LHS &L,
		const RHS &R,
		llvm::Instruction** fmul = nullptr)
{
	return BinaryOp_match<LHS, RHS, llvm::Instruction::FMul>(L, R, fmul);
}

template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, llvm::Instruction::UDiv> m_UDiv(
		const LHS &L,
		const RHS &R,
		llvm::Instruction** udiv = nullptr)
{
	return BinaryOp_match<LHS, RHS, llvm::Instruction::UDiv>(L, R, udiv);
}

template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, llvm::Instruction::SDiv> m_SDiv(
		const LHS &L,
		const RHS &R,
		llvm::Instruction** sdiv = nullptr)
{
	return BinaryOp_match<LHS, RHS, llvm::Instruction::SDiv>(L, R, sdiv);
}

template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, llvm::Instruction::FDiv> m_FDiv(
		const LHS &L,
		const RHS &R,
		llvm::Instruction** fdiv = nullptr)
{
	return BinaryOp_match<LHS, RHS, llvm::Instruction::FDiv>(L, R, fdiv);
}

template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, llvm::Instruction::URem> m_URem(
		const LHS &L,
		const RHS &R,
		llvm::Instruction** urem = nullptr)
{
	return BinaryOp_match<LHS, RHS, llvm::Instruction::URem>(L, R, urem);
}

template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, llvm::Instruction::SRem> m_SRem(
		const LHS &L,
		const RHS &R,
		llvm::Instruction** srem = nullptr)
{
	return BinaryOp_match<LHS, RHS, llvm::Instruction::SRem>(L, R, srem);
}

template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, llvm::Instruction::FRem> m_FRem(
		const LHS &L,
		const RHS &R,
		llvm::Instruction** frem = nullptr)
{
	return BinaryOp_match<LHS, RHS, llvm::Instruction::FRem>(L, R, frem);
}

template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, llvm::Instruction::And> m_And(
		const LHS &L,
		const RHS &R,
		llvm::Instruction** andi = nullptr)
{
	return BinaryOp_match<LHS, RHS, llvm::Instruction::And>(L, R, andi);
}

template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, llvm::Instruction::Or> m_Or(
		const LHS &L,
		const RHS &R,
		llvm::Instruction** ori = nullptr)
{
	return BinaryOp_match<LHS, RHS, llvm::Instruction::Or>(L, R, ori);
}

template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, llvm::Instruction::Xor> m_Xor(
		const LHS &L,
		const RHS &R,
		llvm::Instruction** xori = nullptr)
{
	return BinaryOp_match<LHS, RHS, llvm::Instruction::Xor>(L, R, xori);
}

template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, llvm::Instruction::Shl> m_Shl(
		const LHS &L,
		const RHS &R,
		llvm::Instruction** shl = nullptr)
{
	return BinaryOp_match<LHS, RHS, llvm::Instruction::Shl>(L, R, shl);
}

template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, llvm::Instruction::LShr> m_LShr(
		const LHS &L,
		const RHS &R,
		llvm::Instruction** lshr = nullptr)
{
	return BinaryOp_match<LHS, RHS, llvm::Instruction::LShr>(L, R, lshr);
}

template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, llvm::Instruction::AShr> m_AShr(
		const LHS &L,
		const RHS &R,
		llvm::Instruction** ashr = nullptr)
{
	return BinaryOp_match<LHS, RHS, llvm::Instruction::AShr>(L, R, ashr);
}

//
//==============================================================================
// Binary matchers - commutative.
//==============================================================================
//

template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, llvm::Instruction::Add, true> m_c_Add(
		const LHS &L,
		const RHS &R,
		llvm::Instruction** add = nullptr)
{
	return BinaryOp_match<LHS, RHS, llvm::Instruction::Add, true>(L, R, add);
}

template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, llvm::Instruction::Mul, true> m_c_Mul(
		const LHS &L,
		const RHS &R,
		llvm::Instruction** mul = nullptr)
{
	return BinaryOp_match<LHS, RHS, llvm::Instruction::Mul, true>(L, R, mul);
}

template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, llvm::Instruction::And, true> m_c_And(
		const LHS &L,
		const RHS &R,
		llvm::Instruction** andi = nullptr)
{
	return BinaryOp_match<LHS, RHS, llvm::Instruction::And, true>(L, R, andi);
}

template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, llvm::Instruction::Or, true> m_c_Or(
		const LHS &L,
		const RHS &R,
		llvm::Instruction** ori = nullptr)
{
	return BinaryOp_match<LHS, RHS, llvm::Instruction::Or, true>(L, R, ori);
}

template <typename LHS, typename RHS>
inline BinaryOp_match<LHS, RHS, llvm::Instruction::Xor, true> m_c_Xor(
		const LHS &L,
		const RHS &R,
		llvm::Instruction** xori = nullptr)
{
	return BinaryOp_match<LHS, RHS, llvm::Instruction::Xor, true>(L, R, xori);
}

//
//==============================================================================
// Unary matchers.
//==============================================================================
//

template<typename LHS_t> struct not_match
{
	LHS_t L;

	not_match(const LHS_t& LHS) :
			L(LHS)
	{
	}

	bool match(SymbolicTree& st)
	{
        if (!st.isBinary())
        {
            return false;
        }

		if (auto *O = llvm::dyn_cast<llvm::Operator>(st.value))
		{
			if (O->getOpcode() == llvm::Instruction::Xor)
			{
				if (isAllOnes(st.ops[1].value))
					return L.match(st.ops[0]);
				if (isAllOnes(st.ops[0].value))
					return L.match(st.ops[1]);
			}
		}
		return false;
	}

private:
	bool isAllOnes(llvm::Value *V)
	{
		return llvm::isa<llvm::Constant>(V)
				&& llvm::cast<llvm::Constant>(V)->isAllOnesValue();
	}
};

template<typename LHS> inline not_match<LHS> m_Not(const LHS &L)
{
	return L;
}

template<typename LHS_t> struct neg_match
{
	LHS_t L;

	neg_match(const LHS_t &LHS) :
			L(LHS)
	{
	}

	bool match(SymbolicTree& st)
	{
        if (!st.isBinary())
        {
            return false;
        }

		if (auto *O = llvm::dyn_cast<llvm::Operator>(st.value))
		{
			if (O->getOpcode() == llvm::Instruction::Sub)
			{
				return matchIfNeg(st.ops[0], st.ops[1]);
			}
		}
		return false;
	}

private:
	bool matchIfNeg(SymbolicTree& LHS, SymbolicTree& RHS)
	{
		return ((llvm::isa <llvm::ConstantInt>(LHS.value)
				&& llvm::cast<llvm::ConstantInt>(LHS.value)->isZero())
				|| llvm::isa<llvm::ConstantAggregateZero>(LHS)) && L.match(RHS);
	}
};

/// \brief Match an integer negate.
template<typename LHS> inline neg_match<LHS> m_Neg(const LHS &L)
{
	return L;
}

//
//==============================================================================
// CmpInst matchers - matching Predicate.
//==============================================================================
//

template<
		typename LHS_t,
		typename RHS_t,
		typename Class,
		typename PredicateTy,
		bool Commutable = false>
struct CmpClass_match
{
	PredicateTy& Predicate;
	LHS_t L;
	RHS_t R;
	Class** cmp = nullptr;

	CmpClass_match(
			PredicateTy &Pred,
			const LHS_t &LHS,
			const RHS_t &RHS,
			Class** i = nullptr)
			:
			Predicate(Pred),
			L(LHS),
			R(RHS),
			cmp(i)
	{
	}

	bool match(SymbolicTree& st)
	{
        if (!st.isBinary())
        {
            return false;
        }

		auto *I = llvm::dyn_cast<Class>(st.value);
		if (I == nullptr)
		{
			return false;
		}

		if ((L.match(st.ops[0]) && R.match(st.ops[1]))
				|| (Commutable && L.match(st.ops[1]) && R.match(st.ops[0])))
		{
			if (cmp)
			{
				*cmp = I;
			}
			Predicate = I->getPredicate();
			return true;
		}

		return false;
	}
};

template<typename LHS, typename RHS>
inline CmpClass_match<LHS, RHS, llvm::CmpInst, llvm::CmpInst::Predicate> m_Cmp(
		llvm::CmpInst::Predicate &Pred,
		const LHS &L,
		const RHS &R,
		llvm::CmpInst** cmp = nullptr)
{
	return CmpClass_match<LHS, RHS, llvm::CmpInst, llvm::CmpInst::Predicate>(Pred, L, R, cmp);
}

template<typename LHS, typename RHS>
inline CmpClass_match<LHS, RHS, llvm::ICmpInst, llvm::ICmpInst::Predicate> m_ICmp(
		llvm::ICmpInst::Predicate &Pred,
		const LHS &L,
		const RHS &R,
		llvm::ICmpInst** icmp = nullptr)
{
	return CmpClass_match<LHS, RHS, llvm::ICmpInst, llvm::ICmpInst::Predicate>(Pred, L, R, icmp);
}

template<typename LHS, typename RHS>
inline CmpClass_match<LHS, RHS, llvm::ICmpInst, llvm::ICmpInst::Predicate, true> m_c_ICmp(
		llvm::ICmpInst::Predicate &Pred,
		const LHS &L,
		const RHS &R,
		llvm::ICmpInst** icmp = nullptr)
{
	return CmpClass_match<LHS, RHS, llvm::ICmpInst, llvm::ICmpInst::Predicate, true>(Pred, L, R, icmp);
}

template<typename LHS, typename RHS>
inline CmpClass_match<LHS, RHS, llvm::FCmpInst, llvm::FCmpInst::Predicate> m_FCmp(
		llvm::FCmpInst::Predicate &Pred,
		const LHS &L,
		const RHS &R,
		llvm::FCmpInst** fcmp = nullptr)
{
	return CmpClass_match<LHS, RHS, llvm::FCmpInst, llvm::FCmpInst::Predicate>(Pred, L, R, fcmp);
}

//
//==============================================================================
// CmpInst matchers - checking Predicate.
//==============================================================================
//

template<
		typename LHS_t,
		typename RHS_t,
		typename Class,
		typename PredicateTy,
		bool Commutable = false>
struct CmpClass_pred_match
{
	PredicateTy Predicate;
	LHS_t L;
	RHS_t R;
	Class** cmp = nullptr;

	CmpClass_pred_match(
			PredicateTy Pred,
			const LHS_t &LHS,
			const RHS_t &RHS,
			Class** i = nullptr)
			:
			Predicate(Pred),
			L(LHS),
			R(RHS),
			cmp(i)
	{
	}

	bool match(SymbolicTree& st)
	{
        if (!st.isBinary())
        {
            return false;
        }

		auto *I = llvm::dyn_cast<Class>(st.value);
		if (I == nullptr)
		{
			return false;
		}
		if (I->getPredicate() != Predicate)
		{
			return false;
		}

		if ((L.match(st.ops[0]) && R.match(st.ops[1]))
				|| (Commutable && L.match(st.ops[1]) && R.match(st.ops[0])))
		{
			if (cmp)
			{
				*cmp = I;
			}
			return true;
		}

		return false;
	}
};

template<typename LHS, typename RHS>
inline CmpClass_pred_match<LHS, RHS, llvm::CmpInst, llvm::CmpInst::Predicate> m_Cmp(
		llvm::CmpInst::Predicate Pred,
		const LHS &L,
		const RHS &R,
		llvm::CmpInst** cmp = nullptr)
{
	return CmpClass_pred_match<LHS, RHS, llvm::CmpInst, llvm::CmpInst::Predicate>(Pred, L, R, cmp);
}

template<typename LHS, typename RHS>
inline CmpClass_pred_match<LHS, RHS, llvm::ICmpInst, llvm::ICmpInst::Predicate> m_ICmp(
		llvm::ICmpInst::Predicate Pred,
		const LHS &L,
		const RHS &R,
		llvm::ICmpInst** icmp = nullptr)
{
	return CmpClass_pred_match<LHS, RHS, llvm::ICmpInst, llvm::ICmpInst::Predicate>(Pred, L, R, icmp);
}

template<typename LHS, typename RHS>
inline CmpClass_pred_match<LHS, RHS, llvm::ICmpInst, llvm::ICmpInst::Predicate, true> m_c_ICmp(
		llvm::ICmpInst::Predicate Pred,
		const LHS &L,
		const RHS &R,
		llvm::ICmpInst** icmp = nullptr)
{
	return CmpClass_pred_match<LHS, RHS, llvm::ICmpInst, llvm::ICmpInst::Predicate, true>(Pred, L, R, icmp);
}

template<typename LHS, typename RHS>
inline CmpClass_pred_match<LHS, RHS, llvm::FCmpInst, llvm::FCmpInst::Predicate> m_FCmp(
		llvm::FCmpInst::Predicate Pred,
		const LHS &L,
		const RHS &R,
		llvm::FCmpInst** fcmp = nullptr)
{
	return CmpClass_pred_match<LHS, RHS, llvm::FCmpInst, llvm::FCmpInst::Predicate>(Pred, L, R, fcmp);
}

//
//==============================================================================
// LoadInst matchers.
//==============================================================================
//

template<typename Op_t> struct LoadClass_match
{
	Op_t Op;
	llvm::LoadInst** load = nullptr;

	LoadClass_match(const Op_t &OpMatch, llvm::LoadInst** l = nullptr) :
			Op(OpMatch),
			load(l)
	{
	}

	bool match(SymbolicTree& st)
	{
        if (!st.isUnary())
        {
            return false;
        }

		if (auto *LI = llvm::dyn_cast<llvm::LoadInst>(st.value))
		{
			if (Op.match(st.ops[0]))
			{
				if (load)
				{
					*load = LI;
				}
				return true;
			}
		}
		return false;
	}
};

template<typename OpTy> inline LoadClass_match<OpTy> m_Load(
		const OpTy &Op,
		llvm::LoadInst** l = nullptr)
{
	return LoadClass_match<OpTy>(Op, l);
}

//
//==============================================================================
// Capturing (binding) matchers.
//==============================================================================
//

template <typename Class>
struct bind_ty
{
    Class*& VR;

    bind_ty(Class*& v) :
        VR(v)
    {
    }

    bool match(SymbolicTree& st)
    {
        if (auto* CV = llvm::dyn_cast<Class>(st.value))
        {
            VR = CV;
            return true;
        }
        return false;
    }
};

inline bind_ty<llvm::Value> m_Value(llvm::Value*& V)
{
	return V;
}

inline bind_ty<const llvm::Value> m_Value(const llvm::Value*& V)
{
	return V;
}

inline bind_ty<llvm::BinaryOperator> m_BinOp(llvm::BinaryOperator*& I)
{
	return I;
}

inline bind_ty<llvm::ConstantInt> m_ConstantInt(llvm::ConstantInt*& CI)
{
	return CI;
}

inline bind_ty<llvm::Constant> m_Constant(llvm::Constant*& C)
{
	return C;
}

inline bind_ty<llvm::ConstantFP> m_ConstantFP(llvm::ConstantFP*& C)
{
	return C;
}

inline bind_ty<llvm::GlobalVariable> m_GlobalVariable(llvm::GlobalVariable*& G)
{
	return G;
}

inline bind_ty<llvm::Instruction> m_Instruction(llvm::Instruction*& I)
{
	return I;
}

template<typename Class>
inline bind_ty<Class> m_Instruction(Class*& I)
{
	return I;
}

//
//==============================================================================
// Non-capturing (ignoring) matchers.
//==============================================================================
//

template<typename Class>
struct class_match
{
	bool match(SymbolicTree& st)
	{
		return llvm::isa<Class>(st.value);
	}
};

inline class_match<llvm::Value> m_Value()
{
	return class_match<llvm::Value>();
}

inline class_match<llvm::BinaryOperator> m_BinOp()
{
	return class_match<llvm::BinaryOperator>();
}

inline class_match<llvm::CmpInst> m_Cmp()
{
	return class_match<llvm::CmpInst>();
}

inline class_match<llvm::ConstantInt> m_ConstantInt()
{
	return class_match<llvm::ConstantInt>();
}

inline class_match<llvm::UndefValue> m_Undef()
{
	return class_match<llvm::UndefValue>();
}

inline class_match<llvm::Constant> m_Constant()
{
	return class_match<llvm::Constant>();
}

inline class_match<llvm::Instruction> m_Instruction()
{
	return class_match<llvm::Instruction>();
}

template<typename Class>
inline class_match<Class> m_Instruction()
{
	return class_match<Class>();
}

//
//==============================================================================
// APInt matchers.
//==============================================================================
//

struct apint_match
{
	const llvm::APInt *&Res;

	apint_match(const llvm::APInt *&R) :
			Res(R)
	{
	}

	bool match(SymbolicTree& st)
	{
		if (auto* CI = llvm::dyn_cast<llvm::ConstantInt>(st.value))
		{
			Res = &CI->getValue();
			return true;
		}
		return false;
	}
};

/// \brief Match a ConstantInt, binding the specified pointer to the
/// contained APInt.
inline apint_match m_APInt(const llvm::APInt*& Res)
{
	return Res;
}

//
//==============================================================================
// APFloat matchers.
//==============================================================================
//

struct apfloat_match
{
	const llvm::APFloat*& Res;
	apfloat_match(const llvm::APFloat*& R) :
			Res(R)
	{
	}

	bool match(SymbolicTree& st)
	{
		if (auto *CI = llvm::dyn_cast<llvm::ConstantFP>(st.value))
		{
			Res = &CI->getValueAPF();
			return true;
		}
		return false;
	}
};

/// \brief Match a ConstantFP, binding the specified pointer to the
/// contained APFloat.
inline apfloat_match m_APFloat(const llvm::APFloat*& Res)
{
	return Res;
}

//
//==============================================================================
// Constant int matchers.
//==============================================================================
//

template<int64_t Val> struct constantint_match
{
	bool match(SymbolicTree& st)
	{
		if (const auto* CI = llvm::dyn_cast<llvm::ConstantInt>(st.value))
		{
			const llvm::APInt& CIV = CI->getValue();
			if (Val >= 0)
				return CIV == static_cast<uint64_t>(Val);
			// If Val is negative, and CI is shorter than it, truncate to the
			// right number of bits.  If it is larger, then we have to sign
			// extend.  Just compare their negated values.
			return -CIV == -Val;
		}
		return false;
	}
};

/// \brief Match a ConstantInt with a specific value.
template<int64_t Val> inline constantint_match<Val> m_ConstantInt()
{
	return constantint_match<Val>();
}

//
//==============================================================================
// Zero matchers.
//==============================================================================
//

struct match_zero
{
	bool match(SymbolicTree& st)
	{
		if (const auto* C = llvm::dyn_cast<llvm::Constant>(st.value))
		{
			return C->isNullValue();
		}
		return false;
	}
};

/// \brief Match an arbitrary zero/null constant. This includes
/// zero_initializer for vectors and ConstantPointerNull for pointers.
inline match_zero m_Zero()
{
	return match_zero();
}

struct match_neg_zero
{
	bool match(SymbolicTree& st)
	{
		if (const auto *C = llvm::dyn_cast<llvm::Constant>(st.value))
		{
			return C->isNegativeZeroValue();
		}
		return false;
	}
};

/// \brief Match an arbitrary zero/null constant.  This includes
/// zero_initializer for vectors and ConstantPointerNull for pointers. For
/// floating point constants, this will match negative zero but not positive
/// zero
inline match_neg_zero m_NegZero()
{
	return match_neg_zero();
}

struct match_any_zero
{
	bool match(SymbolicTree& st)
	{
		if (const auto *C = llvm::dyn_cast<llvm::Constant>(st.value))
		{
			return C->isZeroValue();
		}
		return false;
	}
};

/// \brief - Match an arbitrary zero/null constant.  This includes
/// zero_initializer for vectors and ConstantPointerNull for pointers. For
/// floating point constants, this will match negative zero and positive zero
inline match_any_zero m_AnyZero()
{
	return match_any_zero();
}

//
//==============================================================================
// One matchers.
//==============================================================================
//

struct match_one
{
	bool match(SymbolicTree& st)
	{
		if (const auto* C = llvm::dyn_cast<llvm::Constant>(st.value))
		{
			return C->isOneValue();
		}
		return false;
	}
};

inline match_one m_One()
{
	return match_one();
}

//
//==============================================================================
// Specific value matchers.
//==============================================================================
//

struct specificval_ty
{
	const llvm::Value* Val;

	specificval_ty(const llvm::Value* V) :
			Val(V)
	{
	}

	bool match(SymbolicTree& st)
	{
		return st.value == Val;
	}
};

/// \brief Match if we have a specific specified value.
inline specificval_ty m_Specific(const llvm::Value* V)
{
	return V;
}

//
//==============================================================================
// Bind int matchers.
//==============================================================================
//

struct bind_const_intval_ty
{
	uint64_t& VR;

	bind_const_intval_ty(uint64_t &V) :
			VR(V)
	{
	}

	bool match(SymbolicTree& st)
	{
		if (const auto* CV = llvm::dyn_cast<llvm::ConstantInt>(st.value))
		{
			if (CV->getValue().ule(UINT64_MAX))
			{
				VR = CV->getZExtValue();
				return true;
			}
		}
		return false;
	}
};

/// \brief Match a ConstantInt and bind to its value.  This does not match
/// ConstantInts wider than 64-bits.
inline bind_const_intval_ty m_ConstantInt(uint64_t& V)
{
	return V;
}

//
//==============================================================================
// Specific int matchers.
//==============================================================================
//

/// \brief Match a specified integer value.
struct specific_intval
{
	uint64_t Val;

	specific_intval(uint64_t V) :
			Val(V)
	{
	}

	bool match(SymbolicTree& st)
	{
		const auto *CI = llvm::dyn_cast<llvm::ConstantInt>(st.value);
		return CI && CI->getValue() == Val;
	}
};

inline specific_intval m_SpecificInt(uint64_t V)
{
	return specific_intval(V);
}

//
//==============================================================================
// Specific FP matchers.
//==============================================================================
//

/// \brief Match a specified floating point value.
struct specific_fpval
{
	double Val;

	specific_fpval(double V) :
			Val(V)
	{
	}

	template<typename ITy> bool match(ITy *V)
	{
		if (const auto *CFP = llvm::dyn_cast<llvm::ConstantFP>(V))
			return CFP->isExactlyValue(Val);
		return false;
	}
};

inline specific_fpval m_SpecificFP(double V)
{
	return specific_fpval(V);
}

/// \brief Match a float 1.0.
inline specific_fpval m_FPOne()
{
	return m_SpecificFP(1.0);
}

} // namespace st_match
} // namespace bin2llvmir
} // namespace retdec

#endif

/**
* @file src/bin2llvmir/optimizations/cond_branch_opt/cond_branch_opt.cpp
* @brief Conditional branch optimization.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <llvm/IR/Function.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Operator.h>

#include "retdec/bin2llvmir/analyses/symbolic_tree.h"
#include "retdec/bin2llvmir/optimizations/cond_branch_opt/cond_branch_opt.h"
#define debug_enabled false
#include "retdec/bin2llvmir/utils/debug.h"
#include "retdec/bin2llvmir/utils/ir_modifier.h"
#include "retdec/bin2llvmir/utils/symbolic_tree_match.h"

using namespace llvm;
using namespace retdec::bin2llvmir::st_match;

namespace retdec {
namespace bin2llvmir {

char CondBranchOpt::ID = 0;

static RegisterPass<CondBranchOpt> X(
		"cond-branch-opt",
		"Conditional branch optimization",
		false, // Only looks at CFG
		false // Analysis Pass
);

CondBranchOpt::CondBranchOpt() :
		ModulePass(ID)
{

}

bool CondBranchOpt::runOnModule(llvm::Module& m)
{
	_module = &m;
	_config = ConfigProvider::getConfig(_module);
	_abi = AbiProvider::getAbi(_module);
	return run();
}

bool CondBranchOpt::runOnModuleCustom(llvm::Module& m, Config* c, Abi* abi)
{
	_module = &m;
	_config = c;
	_abi = abi;
	return run();
}

bool CondBranchOpt::run()
{
	if (_config == nullptr || _abi == nullptr)
	{
		return false;
	}

	bool changed = false;

	ReachingDefinitionsAnalysis RDA;
	RDA.runOnModule(*_module, _abi, true);

	SymbolicTree::setTrackThroughAllocaLoads(false);
	SymbolicTree::setTrackOnlyFlagRegisters(true);

	for (Function& f : *_module)
	for (auto it = inst_begin(&f), eIt = inst_end(&f); it != eIt;)
	{
		Instruction& insn = *it;
		++it;

		changed |= runOnInstruction(RDA, insn);
	}

	SymbolicTree::setToDefaultConfiguration();

	return changed;
}

bool CondBranchOpt::runOnInstruction(
		ReachingDefinitionsAnalysis& RDA,
		llvm::Instruction& i)
{
	auto* br = dyn_cast<BranchInst>(&i);
	if (br == nullptr || br->isUnconditional())
	{
		return false;
	}
	auto* cond = br->getCondition();

	LOG << llvmObjToString(br) << std::endl;

	SymbolicTree root(RDA, cond);
	LOG << root << std::endl;

	root.simplifyNode();
	LOG << root << std::endl;

	Value* testedVal = nullptr;
	Value* subVal = nullptr;
	Instruction* binOp = nullptr;
	ICmpInst* icmp = nullptr;

	// ZF SF OF xor or
	// ZF OF SF xor or
	// SF OF xor ZF or
	// OF SF xor ZF or
	//
	// => icmp sle
	//
	if (match(root, m_c_Or(
			m_CombineOr(
					m_c_ICmp(ICmpInst::ICMP_NE, m_Instruction<ICmpInst>(), m_Instruction<ICmpInst>()),
					m_c_ICmp(ICmpInst::ICMP_NE, m_Instruction<ICmpInst>(), m_Instruction<ICmpInst>())),
			m_c_ICmp(ICmpInst::ICMP_EQ,
					m_Sub(m_Value(testedVal), m_Value(subVal), &binOp),
					m_Zero()))))
	{
		return transformConditionSub(br, testedVal, subVal, binOp, ICmpInst::ICMP_SLE);
	}
	if (match(root, m_c_Or(
			m_CombineOr(
					m_c_ICmp(ICmpInst::ICMP_NE, m_Instruction<ICmpInst>(), m_Instruction<ICmpInst>()),
					m_c_ICmp(ICmpInst::ICMP_NE, m_Instruction<ICmpInst>(), m_Instruction<ICmpInst>())),
			m_c_ICmp(ICmpInst::ICMP_EQ,
					m_Value(testedVal),
					m_Value(subVal),
					&icmp))))
	{
		return transformConditionSub(br, testedVal, subVal, icmp, ICmpInst::ICMP_SLE);
	}

	// SF OF xor
	// OF SF xor
	//
	// => icmp slt
	//
	if (match(root, m_c_ICmp(ICmpInst::ICMP_NE,
			m_c_ICmp(ICmpInst::ICMP_SLT,
					m_Sub(m_Value(testedVal), m_Value(subVal), &binOp),
					m_Zero()),
			m_c_ICmp(ICmpInst::ICMP_SLT, m_Value(), m_Zero()))))
	{
		return transformConditionSub(br, testedVal, subVal, binOp, ICmpInst::ICMP_SLT);
	}

	// => icmp sgt
	//
	if (match(root, m_c_ICmp(ICmpInst::ICMP_EQ,
			m_c_ICmp(ICmpInst::ICMP_EQ,
					m_c_ICmp(ICmpInst::ICMP_EQ, m_Value(), m_Value()),
					m_Zero()),
			m_c_ICmp(ICmpInst::ICMP_EQ,
					m_c_ICmp(ICmpInst::ICMP_SLT,
							m_Sub(m_Value(testedVal), m_Value(subVal), &binOp),
							m_Value()),
					m_c_ICmp(ICmpInst::ICMP_SLT, m_Value(), m_Value())))))
	{
		return transformConditionSub(br, testedVal, subVal, binOp, ICmpInst::ICMP_SGT);
	}

	// ZF SF OF xor or 1 xor
	// ZF OF SF xor or 1 xor
	// SF OF xor ZF or 1 xor
	// OF SF xor ZF or 1 xor
	//
	// => icmp sgt
	//
	if (match(root, m_c_ICmp(ICmpInst::ICMP_NE,
			m_c_Or(
					m_c_ICmp(ICmpInst::ICMP_NE,
							m_c_ICmp(ICmpInst::ICMP_SLT, m_Value(), m_Value()),
							m_c_ICmp(ICmpInst::ICMP_SLT, m_Value(), m_Value())),
					m_c_ICmp(ICmpInst::ICMP_EQ,
							m_Sub(m_Value(testedVal), m_Value(subVal), &binOp),
							m_Zero())),
			m_One())))
	{
		return transformConditionSub(br, testedVal, subVal, binOp, ICmpInst::ICMP_SGT);
	}
	if (match(root, m_c_ICmp(ICmpInst::ICMP_NE,
			m_c_Or(
					m_c_ICmp(ICmpInst::ICMP_NE,
							m_c_ICmp(ICmpInst::ICMP_SLT, m_Value(), m_Value()),
							m_c_ICmp(ICmpInst::ICMP_SLT, m_Value(), m_Value())),
					m_c_ICmp(ICmpInst::ICMP_EQ,
							m_Value(testedVal),
							m_Value(subVal),
							&icmp)),
			m_One())))
	{
		return transformConditionSub(br, testedVal, subVal, icmp, ICmpInst::ICMP_SGT);
	}

	// 1 SF OF xor xor
	// 1 OF SF xor xor
	// SF OF xor 1 xor
	// OF SF xor 1 xor
	//
	// => icmp sge
	//
	if (match(root, m_c_ICmp(ICmpInst::ICMP_NE,
			m_c_ICmp(ICmpInst::ICMP_NE,
					m_c_ICmp(ICmpInst::ICMP_SLT,
							m_Sub(m_Value(testedVal), m_Value(subVal), &binOp),
							m_Zero()),
					m_c_ICmp(ICmpInst::ICMP_SLT, m_Value(), m_Value())),
			m_One())))
	{
		return transformConditionSub(br, testedVal, subVal, binOp, ICmpInst::ICMP_SGE);
	}

	// => icmp sge
	//
	if (match(root, m_c_ICmp(ICmpInst::ICMP_EQ,
			m_c_ICmp(ICmpInst::ICMP_SLT,
					m_Sub(m_Value(testedVal), m_Value(subVal), &binOp),
					m_Zero()),
			m_c_ICmp(ICmpInst::ICMP_SLT, m_Value(), m_Value()))))
	{
		return transformConditionSub(br, testedVal, subVal, binOp, ICmpInst::ICMP_SGE);
	}

	// 1 ZF xor
	// ZF 1 xor
	//
	// => icmp ne
	//
	if (match(root, m_c_ICmp(ICmpInst::ICMP_NE,
			m_c_ICmp(ICmpInst::ICMP_EQ,
					m_Sub(m_Value(testedVal), m_Value(subVal), &binOp),
					m_Zero()),
			m_One())))
	{
		return transformConditionSub(br, testedVal, subVal, binOp, ICmpInst::ICMP_NE);
	}

	// => icmp ult
	//
	llvm::LoadInst* load = nullptr;
	ConstantInt* ci = nullptr;
	if (match(root, m_c_ICmp(ICmpInst::ICMP_NE,
			m_c_ICmp(ICmpInst::ICMP_UGT,
					m_Load(m_Value(), &load),
					m_ConstantInt(ci)),
			m_One())))
	{
		auto* r = load->getPointerOperand();
		auto* nl = new LoadInst(r, "", br);
		auto* nci = ConstantInt::get(nl->getType(), ci->getZExtValue() - 1);

		if (!nl->getType()->isIntegerTy() || !nci->getType()->isIntegerTy())
		{
			return false;
		}

		auto* icmp = new ICmpInst(br, ICmpInst::ICMP_ULT, nl, nci);
		br->replaceUsesOfWith(br->getCondition(), icmp);
		return true;
	}

	return false;
}

bool CondBranchOpt::transformConditionSub(
		llvm::BranchInst* br,
		llvm::Value* testedVal,
		llvm::Value* subVal,
		llvm::Instruction* binOp,
		llvm::CmpInst::Predicate predicate)
{
	auto* testedA = IrModifier::createAlloca(
			br->getFunction(),
			testedVal->getType());
	auto* subA = IrModifier::createAlloca(
			br->getFunction(),
			subVal->getType());
	if (testedA == nullptr || subA == nullptr)
	{
		return false;
	}
	new StoreInst(testedVal, testedA, binOp);
	new StoreInst(subVal, subA, binOp);

	auto* testedL = new LoadInst(testedA, "", br);
	auto* subL = new LoadInst(subA, "", br);
	auto* conv = IrModifier::convertValueToType(testedL, subL->getType(), br);

	if (!conv->getType()->isIntegerTy() || !subL->getType()->isIntegerTy())
	{
		return false;
	}

	auto* newCond = new ICmpInst(
			br,
			predicate,
			conv,
			subL);

	LOG << "---" << llvmObjToString(br) << std::endl;

	br->replaceUsesOfWith(br->getCondition(), newCond);

	LOG << "+++" << llvmObjToString(newCond) << std::endl;
	LOG << "+++" << llvmObjToString(br) << std::endl;
	return true;
}

} // namespace bin2llvmir
} // namespace retdec

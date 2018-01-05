/**
 * @file src/bin2llvmir/utils/ir_modifier.cpp
 * @brief Modify both LLVM IR and config.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>

#include <llvm/IR/InstIterator.h>

#include "retdec/llvm-support/utils.h"
#include "retdec/utils/string.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"
#include "retdec/bin2llvmir/utils/instruction.h"
#include "retdec/bin2llvmir/utils/ir_modifier.h"
#include "retdec/bin2llvmir/utils/type.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

IrModifier::IrModifier()
{

}

IrModifier::IrModifier(llvm::Module* m, Config* c) :
		_module(m),
		_config(c)
{

}

IrModifier::FunctionPair IrModifier::renameFunction(
		llvm::Function* fnc,
		const std::string& fncName)
{
	auto* cf = _config->getConfigFunction(fnc);
	auto n = retdec::utils::normalizeNamePrefix(fncName);
	if (n == fnc->getName())
	{
		return {fnc, cf};
	}

	fnc->setName(n);
	if (cf)
	{
		cf = _config->renameFunction(cf, fnc->getName());
	}
	else
	{
		cf = _config->insertFunction(fnc);
	}
	return {fnc, cf};
}

IrModifier::FunctionPair IrModifier::splitFunctionOn(
		llvm::Instruction* inst,
		retdec::utils::Address start,
		const std::string& fncName)
{
	auto* cf = _config->getConfigFunction(inst->getFunction());
	assert(cf);

	std::string n = fncName;
	if (n.empty())
	{
		n = retdec::utils::appendHexRet("function", start);
	}

	Function* oldFnc = inst->getFunction();

	std::list<AllocaInst*> allOldAllocas;
	for (inst_iterator it = inst_begin(oldFnc), ee = inst_end(oldFnc); it != ee; ++it)
	{
		Instruction* ii = &(*it);
		if (auto* a = dyn_cast<AllocaInst>(ii))
		{
			allOldAllocas.push_back(a);
		}
	}

	auto* fnc = bin2llvmir::splitFunctionOn(inst, retdec::utils::normalizeNamePrefix(n));
	auto* ncf = _config->insertFunction(fnc, start, cf->getEnd());
	cf->setEnd(start-1);

	std::string bbName = retdec::utils::appendHexRet("dec_label_pc", start);
	fnc->front().setName(bbName);

//==============================================================================
// TODO: not very nice, refactor

	for (auto bbIt = oldFnc->begin(); bbIt != oldFnc->end();)
	{
		bool restart = false;
		auto& bb = *bbIt;
		auto uIt = bb.users().begin();
		while (restart == false && uIt != bb.users().end())
		{
			auto* u = *uIt;
			auto* i = dyn_cast<Instruction>(u);
			assert(i);
			if (i->getFunction() != bb.getParent())
			{
				// TODO: this is not ok, switch was probably badly reconstructed.
				// there should not be functions in switch labels.
				// common problem, more switch tables one after another, we fail
				// to determine switch table bounds, take all the labels from
				// different switch tables.
				// e.g. mips -f elf -c clang -C -O2 --strip P60988.c
				//
				if (auto* sw = dyn_cast<SwitchInst>(i))
				{
					auto* defBb = sw->getDefaultDest();

					if (&bb == defBb)
					{
						if (auto* nextBb = sw->getParent()->getNextNode())
						{
							BranchInst::Create(nextBb, sw);
							sw->eraseFromParent();
						}
						else
						{
							Value* retVal = nullptr;
							if (!sw->getFunction()->getReturnType()->isVoidTy())
							{
								retVal = convertValueToType(
										_config->getGlobalDummy(),
										sw->getFunction()->getReturnType(),
										sw);
							}

							ReturnInst::Create(
									sw->getModule()->getContext(),
									retVal,
									sw);
							sw->eraseFromParent();
						}
					}
					else
					{
						sw->replaceUsesOfWith(&bb, defBb);
					}

					bbIt = fnc->begin();
					restart = true;
					continue;
				}

				auto* br = dyn_cast<BranchInst>(i);
				assert(br);
				if (br->isConditional())
				{
					auto* trueDestUse = br->op_end() - 1;
					auto* trueDestBb = cast<BasicBlock>(trueDestUse->get());
					auto* falseDestUse = br->op_end() - 2;
					auto* falseDestBb = cast<BasicBlock>(falseDestUse->get());

					// L1:
					// ...
					// br F, L1, L2  (L1 in different function)
					// L2:
					// ...
					//
					// ==>
					//
					// fnc_L1():
					// ...
					// br F, L1', L2
					// L1':
					//   call fnc_l1()
					//   ret
					// L2:
					// ...
					//
					if (trueDestBb == &bb)
					{
						auto* nbb = BasicBlock::Create(
								_module->getContext(),
								"",
								falseDestBb->getParent(),
								falseDestBb);
						br->replaceUsesOfWith(&bb, nbb);

						Value* retVal = nullptr;
						if (!i->getFunction()->getReturnType()->isVoidTy())
						{
							retVal = convertConstantToType(
									_config->getGlobalDummy(),
									i->getFunction()->getReturnType());
						}
						auto* term = ReturnInst::Create(_module->getContext(), retVal, nbb);

						auto* first = &bb.front();
						AsmInstruction ai(first);
						if (ai.isValid() && first == ai.getLlvmToAsmInstruction())
						{
							auto* nf = splitFunctionOn(
									ai.getLlvmToAsmInstruction(),
									ai.getAddress()).first;
							CallInst::Create(nf, "", term);
						}
						else
						{
							// TODO: problem -- something is wrong -> ignore for now.
						}
						bbIt = oldFnc->begin();
						restart = true;
						continue;
					}
					else
					{
						assert(false && "label in FALSE branch");
					}
				}
				auto* brBb = br->getParent();

				auto* first = &bb.front();
				AsmInstruction ai(first);
				if (first == ai.getLlvmToAsmInstruction())
				{
					TerminatorInst* term = nullptr;
					if (auto* nextBrBb = brBb->getNextNode())
					{
						term = BranchInst::Create(nextBrBb, br);
					}
					else
					{
						Value* retVal = nullptr;
						if (!i->getFunction()->getReturnType()->isVoidTy())
						{
							retVal = convertConstantToType(
									_config->getGlobalDummy(),
									i->getFunction()->getReturnType());
						}

						term = ReturnInst::Create(_module->getContext(), retVal, br);
					}

					br->eraseFromParent();
					auto* nf = splitFunctionOn(
							ai.getLlvmToAsmInstruction(),
							ai.getAddress()).first;
					CallInst::Create(nf, "", term);
					bbIt = oldFnc->begin();
					restart = true;
					continue;
				}
				else
				{
					if (auto next = ai.getNext())
					{
						TerminatorInst* term = nullptr;
						if (auto* nextBrBb = brBb->getNextNode())
						{
							term = BranchInst::Create(nextBrBb, br);
						}
						else
						{
							Value* retVal = nullptr;
							if (!i->getFunction()->getReturnType()->isVoidTy())
							{
								retVal = convertConstantToType(
										_config->getGlobalDummy(),
										i->getFunction()->getReturnType());
							}

							term = ReturnInst::Create(_module->getContext(), retVal, br);
						}

						br->eraseFromParent();
						auto* nf = splitFunctionOn(
								next.getLlvmToAsmInstruction(),
								next.getAddress()).first;
						CallInst::Create(nf, "", term);
						bbIt = oldFnc->begin();
						restart = true;
						continue;
					}
					else
					{
						auto it = oldFnc->getIterator();
						it++;
						auto* nextFnc = &(*it);
						assert (nextFnc);

						TerminatorInst* term = nullptr;
						if (auto* nextBrBb = brBb->getNextNode())
						{
							term = BranchInst::Create(nextBrBb, br);
						}
						else
						{
							Value* retVal = nullptr;
							if (!i->getFunction()->getReturnType()->isVoidTy())
							{
								retVal = convertConstantToType(
										_config->getGlobalDummy(),
										i->getFunction()->getReturnType());
							}

							term = ReturnInst::Create(_module->getContext(), retVal, br);
						}

						br->eraseFromParent();
						CallInst::Create(nextFnc, "", term);
						bbIt = oldFnc->begin();
						restart = true;
						continue;
					}
				}
			}

			++uIt;
		}

		if (restart)
		{
			bbIt = oldFnc->begin();
		}
		else
		{
			++bbIt;
		}
	}

//==============================================================================
// TODO: not very nice, refactor

	for (auto bbIt = fnc->begin(); bbIt != fnc->end();)
	{
		bool restart = false;

		auto& bb = *bbIt;
		auto uIt = bb.users().begin();
		while (restart == false && uIt != bb.users().end())
		{
			auto* u = *uIt;
			auto* i = dyn_cast<Instruction>(u);
			assert(i);
			if (i->getFunction() != bb.getParent())
			{
				// TODO: this is not ok, switch was probably badly reconstructed.
				// there should not be functions in switch labels.
				// common problem, more switch tables one after another, we fail
				// to determine switch table bounds, take all the labels from
				// different switch tables.
				// e.g. mips -f elf -c clang -C -O2 --strip P60988.c
				//
				if (auto* sw = dyn_cast<SwitchInst>(i))
				{
					auto* defBb = sw->getDefaultDest();

					if (&bb == defBb)
					{
						if (auto* nextBb = sw->getParent()->getNextNode())
						{
							BranchInst::Create(nextBb, sw);
							sw->eraseFromParent();
						}
						else
						{
							Value* retVal = nullptr;
							if (!sw->getFunction()->getReturnType()->isVoidTy())
							{
								retVal = convertValueToType(
										_config->getGlobalDummy(),
										sw->getFunction()->getReturnType(),
										sw);
							}

							ReturnInst::Create(
									sw->getModule()->getContext(),
									retVal,
									sw);
							sw->eraseFromParent();
						}
					}
					else
					{
						sw->replaceUsesOfWith(&bb, defBb);
					}

					bbIt = fnc->begin();
					restart = true;
					continue;
				}

				auto* br = dyn_cast<BranchInst>(i);
				assert(br);
//				assert(!br->isConditional());
				if (br->isConditional())
				{
					auto* trueDestUse = br->op_end() - 1;
					auto* trueDestBb = cast<BasicBlock>(trueDestUse->get());
					auto* falseDestUse = br->op_end() - 2;
					auto* falseDestBb = cast<BasicBlock>(falseDestUse->get());

					// L1:
					// ...
					// br F, L1, L2  (L1 in different function)
					// L2:
					// ...
					//
					// ==>
					//
					// fnc_L1():
					// ...
					// br F, L1', L2
					// L1':
					//   call fnc_l1()
					//   ret
					// L2:
					// ...
					//
					if (trueDestBb == &bb)
					{
						auto* nbb = BasicBlock::Create(
								_module->getContext(),
								"",
								falseDestBb->getParent(),
								falseDestBb);
						br->replaceUsesOfWith(&bb, nbb);

						Value* retVal = nullptr;
						if (!i->getFunction()->getReturnType()->isVoidTy())
						{
							retVal = convertConstantToType(
									_config->getGlobalDummy(),
									i->getFunction()->getReturnType());
						}
						auto* term = ReturnInst::Create(_module->getContext(), retVal, nbb);

						auto* first = &bb.front();
						AsmInstruction ai(first);
						if (ai.isValid() && first == ai.getLlvmToAsmInstruction())
						{
							auto* nf = splitFunctionOn(
									ai.getLlvmToAsmInstruction(),
									ai.getAddress()).first;
							CallInst::Create(nf, "", term);
						}
						else
						{
							// TODO: problem -- something is wrong -> ignore for now.
						}

						bbIt = fnc->begin();
						restart = true;
						continue;
					}
					else
					{
						assert(false && "label in FALSE branch");
					}
				}

				auto* brBb = br->getParent();

				auto* first = &bb.front();
				AsmInstruction ai(first);
				if (first == ai.getLlvmToAsmInstruction())
				{
					TerminatorInst* term = nullptr;
					if (auto* nextBrBb = brBb->getNextNode())
					{
						term = BranchInst::Create(nextBrBb, br);
					}
					else
					{
						Value* retVal = nullptr;
						if (!i->getFunction()->getReturnType()->isVoidTy())
						{
							retVal = convertConstantToType(
									_config->getGlobalDummy(),
									i->getFunction()->getReturnType());
						}

						term = ReturnInst::Create(_module->getContext(), retVal, br);
					}

					br->eraseFromParent();
					auto* nf = splitFunctionOn(
							ai.getLlvmToAsmInstruction(),
							ai.getAddress()).first;
					CallInst::Create(nf, "", term);
					bbIt = fnc->begin();
					restart = true;
					continue;
				}
				else
				{
					if (auto next = ai.getNext())
					{
						TerminatorInst* term = nullptr;
						if (auto* nextBrBb = brBb->getNextNode())
						{
							term = BranchInst::Create(nextBrBb, br);
						}
						else
						{
							Value* retVal = nullptr;
							if (!i->getFunction()->getReturnType()->isVoidTy())
							{
								retVal = convertConstantToType(
										_config->getGlobalDummy(),
										i->getFunction()->getReturnType());
							}

							term = ReturnInst::Create(_module->getContext(), retVal, br);
						}

						br->eraseFromParent();
						auto* nf = splitFunctionOn(
								next.getLlvmToAsmInstruction(),
								next.getAddress()).first;
						CallInst::Create(nf, "", term);
						bbIt = fnc->begin();
						restart = true;
						continue;
					}
					else
					{
						auto it = fnc->getIterator();
						it++;
						auto* nextFnc = &(*it);
						assert (nextFnc);

						TerminatorInst* term = nullptr;
						if (auto* nextBrBb = brBb->getNextNode())
						{
							term = BranchInst::Create(nextBrBb, br);
						}
						else
						{
							Value* retVal = nullptr;
							if (!i->getFunction()->getReturnType()->isVoidTy())
							{
								retVal = convertConstantToType(
										_config->getGlobalDummy(),
										i->getFunction()->getReturnType());
							}

							term = ReturnInst::Create(_module->getContext(), retVal, br);
						}

						br->eraseFromParent();
						CallInst::Create(nextFnc, "", term);
						bbIt = fnc->begin();
						restart = true;
						continue;
					}
				}
			}

			++uIt;
		}

		if (restart)
		{
			bbIt = fnc->begin();
		}
		else
		{
			++bbIt;
		}
	}

//==============================================================================
// TODO: not very nice, refactor

	for (auto* a : allOldAllocas)
	{
		std::list<std::pair<Instruction*, AllocaInst*>> toReplace;
		std::map<Function*, AllocaInst*> fnc2alloca;

		for (auto* u : a->users())
		{
			auto* inst = dyn_cast<Instruction>(u);
			assert(inst);

			if (inst->getFunction() != a->getFunction())
			{
				auto fIt = fnc2alloca.find(inst->getFunction());
				if (fIt == fnc2alloca.end())
				{
					auto it = inst_begin(inst->getFunction());
					assert(it != inst_end(inst->getFunction()));
					auto* firstI = &*it;

					auto* na = new AllocaInst(a->getAllocatedType(), "", firstI);
					fnc2alloca[inst->getFunction()] = na;
					toReplace.push_back({inst, na});
				}
				else
				{
					toReplace.push_back({inst, fIt->second});
				}
			}
		}

		for (auto& p : toReplace)
		{
			p.first->replaceUsesOfWith(a, p.second);
		}
	}

//==============================================================================

	return {fnc, ncf};
}

IrModifier::FunctionPair IrModifier::addFunction(
		retdec::utils::Address start,
		const std::string& fncName)
{
	FunctionType* voidT = FunctionType::get(
			getDefaultType(_module),
			false);

	std::string n = fncName;
	if (n.empty())
	{
		n = retdec::utils::appendHexRet("function", start);
	}

	auto* fnc = Function::Create(
			voidT,
			GlobalValue::ExternalLinkage,
			retdec::utils::normalizeNamePrefix(n),
			_module);

	auto* cf = _config->insertFunction(fnc, start, start);

	return {fnc, cf};
}

IrModifier::FunctionPair IrModifier::addFunctionUnknown(
		retdec::utils::Address start)
{
	std::string n = retdec::utils::appendHexRet("unknown", start);
	return addFunction(start, n);
}

/**
 * Get or create&get stack variable.
 * @param fnc    Function owning the stack variable.
 * @param offset Stack varibale's offset.
 * @param type   Stack varibale's type.
 * @param name   Stack varibale's name in IR. If not set default name is used.
 *               Offset is always appended to this name. If you want to get
 *               this name to output C, set it as a real name to returned
 *               config stack variable entry.
 * @return Pair of LLVM stack var (Alloca instruction) and associated config
 *         stack var.
 */
IrModifier::StackPair IrModifier::getStackVariable(
		llvm::Function* fnc,
		int offset,
		llvm::Type* type,
		const std::string& name)
{
	if (!PointerType::isValidElementType(type))
	{
		type = getDefaultType(fnc->getParent());
	}

	std::string n = name.empty() ? "stack_var" : name;
	n += "_" + std::to_string(offset);
	AllocaInst* ret = _config->getLlvmStackVariable(fnc, offset);
	if (ret)
	{
//		assert(type == ret->getAllocatedType()); // -> change type?
//		assert(n == ret->getName()); // -> change name?
		auto* csv = _config->getConfigStackVariable(ret);
		assert(csv);
		return {ret, csv};
	}

	ret = new AllocaInst(type, n);

	auto it = inst_begin(fnc);
	assert(it != inst_end(fnc)); // -> create bb, insert alloca.
	ret->insertBefore(&*it);

	auto* csv = _config->insertStackVariable(ret, offset);

	return {ret, csv};
}

} // namespace bin2llvmir
} // namespace retdec

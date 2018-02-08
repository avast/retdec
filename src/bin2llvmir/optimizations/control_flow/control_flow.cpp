/**
* @file src/bin2llvmir/optimizations/control_flow/control_flow.cpp
* @brief Reconstruct control flow.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <llvm/IR/Constants.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Operator.h>

#include "retdec/bin2llvmir/optimizations/control_flow/control_flow.h"
#include "retdec/bin2llvmir/providers/lti.h"
#include "retdec/bin2llvmir/utils/global_var.h"
#include "retdec/bin2llvmir/utils/ir_modifier.h"
#include "retdec/bin2llvmir/utils/type.h"
#define debug_enabled false
#include "retdec/llvm-support/utils.h"

using namespace retdec::llvm_support;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {

char ControlFlow::ID = 0;

static RegisterPass<ControlFlow> X(
		"control-flow",
		"Control flow optimization",
		false, // Only looks at CFG
		false // Analysis Pass
);

ControlFlow::ControlFlow() :
		ModulePass(ID)
{

}

bool ControlFlow::runOnModule(llvm::Module& m)
{
	_module = &m;
	_config = ConfigProvider::getConfig(_module);
	_image = FileImageProvider::getFileImage(_module);
	return run();
}

bool ControlFlow::runOnModuleCustom(
		llvm::Module& m,
		Config* c,
		FileImage* img)
{
	_module = &m;
	_config = c;
	_image = img;
	return run();
}

bool ControlFlow::run()
{
	if (_config == nullptr || _image == nullptr)
	{
		return false;
	}

//dumpModuleToFile(_module);

	bool changed = false;
	_irmodif = IrModifier(_module, _config);

	if (_config->getConfig().architecture.isX86())
	{
		changed |= runX86();
	}
	else if (_config->isMipsOrPic32())
	{
		changed |= runMips();
	}
	else if (_config->getConfig().architecture.isArmOrThumb())
	{
		changed |= runArm();
	}
	else if (_config->getConfig().architecture.isPpc())
	{
		changed |= runPowerpc();
	}

	toReturn();
	toCall();
	toBr();
	toCondBr();
	toSwitch();

	changed |= runGeneric();

	toFunction();
	toReturn();
	toCall();
	toBr();
	toCondBr();
	toSwitch();

	if (_config->getConfig().architecture.isX86())
	{
		changed |= runX86JmpNopNopPattern();
	}

	_RDA.runOnModule(*_module, _config, true);

	if (_config->getConfig().architecture.isArmOrThumb())
	{
		changed |= runArm();
	}

	toReturn();
	toCall();
	toBr();
	toCondBr();
	toSwitch();

	if (_config->isMipsOrPic32())
	{
		changed |= runMipsDynamicStubPatter();
	}

	changed |= runGeneric();

	toFunction();
	toReturn();
	toCall();
	toBr();
	toCondBr();
	toSwitch();

	_RDA.clear();

	toFunction();

	if (_config->isMipsOrPic32())
	{
		changed |= runMipsDynamicStubPatter();
	}

	changed |= fixMain();

//dumpModuleToFile(_module);

	return changed;
}

bool ControlFlow::fixMain()
{
	if (_config->getConfig().isIda())
	{
		return false;
	}

	if (_module->getFunction("main") == nullptr)
	{
		if (auto* m = _module->getFunction("_main"))
		{
			_irmodif.renameFunction(m, "main");
			return true;
		}
		else if (auto* m = _module->getFunction("wmain"))
		{
			_irmodif.renameFunction(m, "main");
			return true;
		}
	}
	return false;
}

bool ControlFlow::toFunction()
{
	bool changed = false;

	for (auto& ai : _toFunctions)
	{
		std::string n;
		if (auto* sym = _image->getPreferredSymbol(ai.getAddress()))
		{
			n = sym->getName();
		}

		_irmodif.splitFunctionOn(
				ai.getLlvmToAsmInstruction(),
				ai.getAddress(),
				n);
		changed |= true;
	}

	_toFunctions.clear();
	return changed;
}

bool ControlFlow::toReturn()
{
	bool changed = false;

	for (auto& p : _toReturn)
	{
		AsmInstruction ai = p.first;
		CallInst* c = p.second;

		LOG << std::endl << ai;

		transformToReturn(ai, c);
		changed |= true;

		LOG << "==>\n" << ai << std::endl;
	}

	_toReturn.clear();
	return changed;
}

bool ControlFlow::toCall()
{
	bool changed = false;

	for (auto& p : _toCall)
	{
		CallInst* c = p.first;
		retdec::utils::Address target = p.second;
		AsmInstruction ai(c);

		LOG << std::endl << ai;

		auto* f = getOrMakeFunction(target);
		transformToCall(ai, c, f);
		changed |= true;

		LOG << "==>\n" << ai << std::endl;
	}

	_toCall.clear();
	return changed;
}

bool ControlFlow::toBr()
{
	bool changed = false;

	for (auto& p : _toBr)
	{
		CallInst* call = p.first;
		AsmInstruction aiTarget = p.second;
		AsmInstruction aiSource(call);

		if (auto* f = _config->getLlvmFunction(aiTarget.getAddress()))
		{
			transformToCall(aiSource, call, f);
			continue;
		}
		// TODO
		// Sometimes function is at X, and its first instruction at e.g. X+5.
		// Then _config->getLlvmFunction() will not succeed, but we still need
		// to generate call, instead of branch -- first BB can not have
		// predecessors.
		// e.g. function_100059b7 in x86-pe-005da177d87522ba3df0f0995aeb6652
		// first instruction is 100059bf. This is because it is function after
		// statically linked code, jump target created as SYMBOL_FUNCTION,
		// which prevents decoder from fixing the function start address.
		if (aiTarget.getPrev().isInvalid())
		{
			transformToCall(aiSource, call, aiTarget.getFunction());
			continue;
		}
		if (aiTarget.getFunction() != aiSource.getFunction())
		{
			auto* f = getOrMakeFunction(aiTarget.getAddress());
			transformToCall(aiSource, call, f);
			continue;
		}

		LOG << std::endl << aiSource;

		auto* bbTarget = aiTarget.makeStart();
		auto* term = aiSource.makeTerminal();
		BranchInst::Create(bbTarget, term);
		term->eraseFromParent();
		call->eraseFromParent();

		LOG << "==>\n" << aiSource << std::endl;
		changed |= true;
	}

	_toBr.clear();
	return changed;
}

bool ControlFlow::toCondBr()
{
	bool changed = false;

	for (auto& p : _toCondBr)
	{
		CallInst* call = p.first;
		AsmInstruction aiTarget = p.second;
		AsmInstruction aiSource(call);
		Value* cond = call->getArgOperand(0);

		if (aiSource.getFunction() != aiTarget.getFunction())
		{
			continue;
		}

		LOG << std::endl << aiSource;

		auto* bbTarget = aiTarget.makeStart();
		auto* tterm = aiSource.makeTerminal();

		if (auto* term = dyn_cast<BranchInst>(tterm))
		{
			BranchInst::Create(bbTarget, term->getSuccessor(0), cond, term);
			term->eraseFromParent();
			call->eraseFromParent();

			// Entry block must not have predecessors.
			if (bbTarget == &bbTarget->getParent()->front())
			{
				auto* sbb = BasicBlock::Create(
						_module->getContext(),
						"",
						bbTarget->getParent(),
						bbTarget);
				BranchInst::Create(bbTarget, sbb);
			}

			LOG << "==>" << std::endl << aiSource << std::endl;
			changed |= true;
			continue;
		}
		else if (auto* ret = dyn_cast<ReturnInst>(tterm))
		{
			BasicBlock* retBb = nullptr;
			if (&ret->getParent()->front() == ret)
			{
				retBb = ret->getParent();
			}
			else
			{
				retBb = ret->getParent()->splitBasicBlock(ret);
			}
			auto* term = call->getParent()->getTerminator();
			BranchInst::Create(bbTarget, retBb, cond, term);
			term->eraseFromParent();
			call->eraseFromParent();

			// Entry block must not have predecessors.
			if (bbTarget == &bbTarget->getParent()->front())
			{
				auto* sbb = BasicBlock::Create(
						_module->getContext(),
						"",
						bbTarget->getParent(),
						bbTarget);
				BranchInst::Create(bbTarget, sbb);
			}

			LOG << "==>" << std::endl << aiSource << std::endl;
			changed |= true;
			continue;
		}
		else
		{
			assert(false);
		}
	}

	_toCondBr.clear();
	return changed;
}

bool ControlFlow::toSwitch()
{
	bool changed = false;

	for (auto& e : _toSwitch)
	{
		CallInst* call = e.call;
		AsmInstruction aiSource = e.aiSource;
		BasicBlock* defaultBb = e.defaultBb;
		auto defaultAi = AsmInstruction(defaultBb);

		if (!e.idx->getType()->isIntegerTy())
		{
			continue;
		}
		if (_config->getLlvmFunction(defaultAi.getAddress()))
		{
			continue;
		}
		if (aiSource.getFunction() != defaultAi.getFunction())
		{
			continue;
		}
		bool ok = true;
		for (auto& p : e.jmpTable)
		{
			auto targetAi = p.second;
			if (aiSource.getFunction() != targetAi.getFunction())
			{
				ok = false;
				break;
			}
			if (_config->getLlvmFunction(targetAi.getAddress()))
			{
				ok = false;
				break;
			}
		}
		if (!ok)
		{
			continue;
		}

		LOG << std::endl << aiSource;

		std::vector<std::pair<unsigned, BasicBlock*>> jmpTable;
		for (auto& p : e.jmpTable)
		{
			auto targetAi = p.second;
			auto* targetBb = targetAi.makeStart();
			if (targetAi == defaultAi)
			{
				// nothing -- default.
			}
			else
			{
				jmpTable.push_back({p.first, targetBb});
			}
		}

		auto it = inst_begin(call->getFunction());
		assert(it != inst_end(call->getFunction()));
		auto* firstI = &*it;

		auto* conv = convertValueToTypeAfter(
				e.idx,
				getDefaultType(_module),
				e.idx);
		auto* idxA = new AllocaInst(
				conv->getType(),
				"",
				firstI);
		auto* s = new StoreInst(conv, idxA);
		s->insertAfter(cast<Instruction>(conv));

		auto* term = aiSource.makeTerminal();
		auto* idxL = new LoadInst(idxA, "", term);
		auto* switchI = SwitchInst::Create(idxL, defaultBb, unsigned(jmpTable.size()), term);
		term->eraseFromParent();
		call->eraseFromParent();

		for (auto& p : jmpTable)
		{
			switchI->addCase(
					ConstantInt::get(getDefaultType(_module), p.first),
					p.second);
		}

		// On ARM, ucond branch is in cond if-then pattern of cond ASM insn.
		// We need to make sure if always goes into body, if we transformed
		// branch in body into switch.
		//
		if (aiSource.isConditional(_config))
		{
			auto* br = aiSource.getInstructionFirst<BranchInst>();
			if (br && br->isConditional())
			{
				br->setCondition(ConstantInt::getTrue(_module->getContext()));
			}
		}

		LOG << "==>\n" << aiSource << std::endl;
		changed |= true;
	}

	_toSwitch.clear();
	return changed;
}

bool ControlFlow::runGeneric()
{
	bool changed = false;
	for (auto& f : *_module)
	{
		changed |= runGenericFunction(&f);
	}
	return changed;
}

bool ControlFlow::runGenericFunction(llvm::Function* f)
{
	bool changed = false;
	for (auto ai = AsmInstruction(f); ai.isValid(); ai = ai.getNext())
	for (auto& i : ai)
	{
		if (auto* c = _config->isLlvmAnyUncondBranchPseudoFunctionCall(&i))
		{
			changed |= runGenericBr(ai, c);
		}
		else if (auto* c = _config->isLlvmCondBranchPseudoFunctionCall(&i))
		{
			changed |= runGenericCondBr(ai, c);
		}
	}
	return changed;
}

bool ControlFlow::runGenericBr(AsmInstruction& ai, llvm::CallInst* call)
{
	bool changed = false;

	auto* op = call->getArgOperand(0);

	// decode__instr_grp32_4_m32__instr_jmp_4_rmxx__MODRM32_4_mem32__MODRM32_mod00_32_4_disp32__uimm32__
	// %u1_4074f0 = load i32, i32* inttoptr (i32 4239780 to i32*), align 4
	// call void @__pseudo_br(i32 %u1_4074f0)
	//
	if (auto* l = dyn_cast<LoadInst>(op))
	{
		if (auto* ci = dyn_cast<ConstantInt>(skipCasts(l->getPointerOperand())))
		{
			_toCall.insert({call, ci->getZExtValue()});
			return true;
		}
	}

	if (auto* ci = dyn_cast<ConstantInt>(op))
	{
		if (auto aiTarget = AsmInstruction(_module, ci->getZExtValue()))
		{
			if (aiTarget.getFunction() != call->getFunction())
			{
				_toCall.insert({call, aiTarget.getAddress()});
				return true;
			}
			else
			{
				_toBr.insert({call, aiTarget});
				return true;
			}
		}
		else
		{
			_toCall.insert({call, ci->getZExtValue()});
			return true;
		}
	}
	else
	{
		// TODO -- call variable
		// 1.) if RDA available, try to compute it.
		// 2.) if not computed, transform to call of variable.

		if (!_RDA.wasRun())
		{
			return false;
		}

		SymbolicTree root(_RDA, call->getArgOperand(0));

		// PIC code.
		// User code is calling stub in .plt.
		// Stub in .plt is computing jmp address (address of import).
		// 4-form_grabber-b794ce9e.so.elf, .plt:00001BE0 ___ctype_toupper_loc:
		//   %u1_1be0 = load i32, i32* @ebx
		//   %u2_1be0 = add i32 %u1_1be0, %u0_1be0
		//   %u3_1be0 = load i32, i32* %u2_1be0
		//   call void @__pseudo_br(i32 %u3_1be0)
		// We do not know the value in @ebx. This should be .got.plt section
		// start -> fix value in symbolic tree before simplification.
		//
		auto* plt = _image->getFileFormat()->getSectionFromAddress(ai.getAddress());
		if (plt && plt->getName() == ".plt")
		{
			auto* gotplt = _image->getFileFormat()->getSection(".got.plt");
			if (gotplt)
			{
				auto gotpltAddr = gotplt->getAddress();
				for (auto* n : root.getPostOrder())
				{
					if (_config->isGeneralPurposeRegister(n->value)
							&& n->ops.size() == 1
							&& isa<ConstantInt>(n->ops[0].value))
					{
						auto* ci = cast<ConstantInt>(n->ops[0].value);
						n->ops[0].value = ConstantInt::get(
								ci->getType(),
								gotpltAddr);
					}
				}
			}
		}

		root.simplifyNode(_config);

		auto* bOp = dyn_cast<BinaryOperator>(root.value);
		if (bOp
				&& bOp->getOpcode() == BinaryOperator::And
				&& root.ops.size() == 2
				&& isa<ConstantInt>(root.ops[1].value))
		{
			auto* ci = cast<ConstantInt>(root.ops[1].value);
			if (ci->getSExtValue() == -2)
			{
				root = std::move(root.ops[0]);
			}
		}

		if (dyn_cast_or_null<ConstantInt>(root.value))
		{
//			assert(false);
		}
		else if (isa<LoadInst>(root.value)
				&& root.ops.size() == 1
				&& isa<ConstantInt>(root.ops[0].value))
		{
			auto* ci1 = cast<ConstantInt>(root.ops[0].value);
			auto* ci2 = _image->getConstantDefault(ci1->getZExtValue());
			auto* ci2Fnc = ci2 ? _config->getLlvmFunction(ci2->getZExtValue()) : nullptr;
			auto* ci2CFnc = ci2Fnc ? _config->getConfigFunction(ci2Fnc) : nullptr;

			if (ci2 && !ci2->isZero() && ci2Fnc && ci2CFnc
					&& (ci2CFnc->isDynamicallyLinked() || ci2CFnc->isStaticallyLinked()))
			{
			   _toCall.insert({call, ci2->getZExtValue()});
			   return true;
			}
			else if (auto* llvmFnc = _config->getLlvmFunction(ci1->getZExtValue()))
			{
				// control flow function detection
				// in ack.powerpc.gcc-4.5.1.O0.g.elf @ 10000790,
				// there is some code unassociated with any function.
				// TODO: terminating function calls -> next is not stored to LR.
				//
				if (_config->getConfig().architecture.isPpc()
						&& &ai.getFunction()->front() == ai.getBasicBlock()
						&& llvmFnc->isDeclaration())
				{
					auto next = ai.getNext();
					if (next.isValid())
					{
						_toFunctions.insert(next);
					}
				}

				_toCall.insert({call, ci1->getZExtValue()});
				return true;
			}
			else if (ci2)
			{
				_toCall.insert({call, ci2->getZExtValue()});
				return true;
			}
		}
		else if (isa<LoadInst>(root.value)
				&& root.ops.size() == 1
				&& isa<LoadInst>(root.ops[0].value)
				&& root.ops[0].ops.size() == 1
				&& isa<ConstantInt>(root.ops[0].ops[0].value))
		{
			auto* ci1 = dyn_cast<ConstantInt>(root.ops[0].ops[0].value);
			auto* ci2 = _image->getConstantDefault(ci1->getZExtValue());
			if (ci2 == nullptr)
			{
				return false;
			}

			if (_config->getLlvmFunction(ci2->getZExtValue()))
			{
//				transformToCall(ai, call, cf1);
				_toCall.insert({call, ci2->getZExtValue()});
				return true;
			}
		}
		// Switch patterns.
		//
		// switch.x86.mingw32-gcc-4.7.3.O0.g.ex:
		//>|   %u6_4017c9 = load i32, i32* %conv_4017c9_0, align 4
		//		>|   %u5_4017c9 = add i32 %u4_4017c9, 4231312
		//				>|   %u4_4017c9 = mul i32 %u2_4017c9, 4
		//						>|   %u6_4017c1 = add i32 %u2_4017c1, -20
		//								>|   %u1_4017bc = load i32, i32* inttoptr (i32 4238732 to i32*), align 4
		//										>| i32 4238732
		//								>| i32 -20
		//						>| i32 4
		//				>| i32 4231312
		//
		// switch.x86.clang-3.2.O0.g.ex:
		//>|   %u6_401913 = load i32, i32* %conv_401913_0, align 4
		//		>|   %u5_401913 = add i32 %u4_401913, 4231236
		//				>|   %u4_401913 = mul i32 %u2_401913, 4
		//						>|   %u4_401910 = load i32, i32* %conv_401910_0, align 4
		//								>| i32 -12   // stack -12,
		//						>| i32 4
		//				>| i32 4231236
		//
		// TODO: if we do not get index sub value, we do not know the size of the
		// table -> if there are consequent
		//
		if (_config->getConfig().architecture.isArmOrThumb())
		{
			root.solveMemoryLoads(_image);
		}

		root.simplifyNode(_config);

		if (isa<LoadInst>(root.value)
				&& root.ops.size() == 1
				&& isa<AddOperator>(root.ops[0].value)
				&& root.ops[0].ops.size() == 2
				&& isa<ConstantInt>(root.ops[0].ops[1].value)
				&& (isa<MulOperator>(root.ops[0].ops[0].value) || isa<ShlOperator>(root.ops[0].ops[0].value))
				&& root.ops[0].ops[0].ops.size() == 2
				&& isa<ConstantInt>(root.ops[0].ops[0].ops[1].value)
				&& isa<Instruction>(root.ops[0].ops[0].ops[0].value)
				&& cast<Instruction>(root.ops[0].ops[0].ops[0].value)->getType()->isIntegerTy())
//				&& isa<AddOperator>(root.ops[0].ops[0].ops[0].value)) // switch.x86.mingw32-gcc-4.7.3.O0.g.ex
		{
			auto* tableAddrConst = cast<ConstantInt>(root.ops[0].ops[1].value);
			retdec::utils::Address tableAddr(tableAddrConst->getZExtValue());

			auto* mulValConst = cast<ConstantInt>(root.ops[0].ops[0].ops[1].value); // TODO: or shl const
			auto* idx = cast<Instruction>(root.ops[0].ops[0].ops[0].value);

			BranchInst* condBr = nullptr;

			if (!ai.isConditional(_config))
			{
				auto aiPrev = ai.getPrev();
				while (aiPrev.isValid())
				{
					for (auto& i : aiPrev)
					{
						if (auto* br = dyn_cast<BranchInst>(&i))
						{
							if (br->isConditional())
							{
								condBr = br;
								break;
							}
						}
					}
					if (condBr)
					{
						break;
					}
					aiPrev = aiPrev.getPrev();
				}
			}
			else
			{
				auto aiNext = ai.getNext();
				for (auto& i : aiNext)
				{
					if (auto* br = dyn_cast<BranchInst>(&i))
					{
						if (br->isUnconditional())
						{
							condBr = br;
							break;
						}
					}
				}
			}

			if (condBr == nullptr)
			{
				return false;
			}
			assert(condBr);

			retdec::utils::Maybe<unsigned> tableSize;

			if (condBr->isConditional())
			{
				auto* condVal = condBr->getCondition();
				SymbolicTree rootCond(_RDA, condVal);
				rootCond.simplifyNode(_config);
				LOG << rootCond << std::endl;
				auto pre = rootCond.getPreOrder();
				for (SymbolicTree* n : pre)
				{
					if (isa<BinaryOperator>(n->value)
							&& cast<BinaryOperator>(n->value)->getOpcode() == Instruction::Or
							&& n->ops.size() == 2
							&& isa<ICmpInst>(n->ops[0].value)
							&& cast<ICmpInst>(n->ops[0].value)->getPredicate() == ICmpInst::ICMP_ULT
							&& n->ops[0].ops.size() == 2
							&& isa<ConstantInt>(n->ops[0].ops[1].value)
							&& isa<ICmpInst>(n->ops[1].value)
							&& cast<ICmpInst>(n->ops[1].value)->getPredicate() == ICmpInst::ICMP_EQ
							&& n->ops[1].ops.size() == 2
							&& isa<ConstantInt>(n->ops[1].ops[1].value)
							&& cast<ConstantInt>(n->ops[1].ops[1].value)->isZero())
					{
						auto* ci = cast<ConstantInt>(n->ops[0].ops[1].value);
						tableSize = ci->getZExtValue() + 1;
						break;
					}
					// TODO: ackermann.arm.clang-3.2.O0.g.elf @ 000086E8
					// These kind of patterns should all be simplified by some analysis.
//					/
					else if (isa<BinaryOperator>(n->value)
							&& cast<BinaryOperator>(n->value)->getOpcode() == Instruction::And
							&& n->ops.size() == 2
							&& isa<ICmpInst>(n->ops[0].value)
							&& cast<ICmpInst>(n->ops[0].value)->getPredicate() == ICmpInst::ICMP_ULT
							&& n->ops[0].ops.size() == 2
							&& isa<ConstantInt>(n->ops[0].ops[1].value)
							&& isa<BinaryOperator>(n->ops[1].value)
							&& cast<BinaryOperator>(n->ops[1].value)->getOpcode() == Instruction::Xor
							&& n->ops[1].ops.size() == 2
							&& isa<ICmpInst>(n->ops[1].ops[0].value)
							&& cast<ICmpInst>(n->ops[1].ops[0].value)->getPredicate() == ICmpInst::ICMP_EQ)
					{
						auto* ci = cast<ConstantInt>(n->ops[0].ops[1].value);
						tableSize = ci->getZExtValue() + 1;
						break;
					}
					else if (isa<ICmpInst>(n->value)
							&& cast<ICmpInst>(n->value)->getPredicate() == ICmpInst::ICMP_ULT
							&& n->ops.size() == 2
							&& isa<ConstantInt>(n->ops[1].value))
					{
						auto* ci = cast<ConstantInt>(n->ops[1].value);
						tableSize = ci->getZExtValue();
						break;
					}
				}
				condBr->setCondition(ConstantInt::getFalse(_module->getContext()));
			}

			BasicBlock* defaultBb = condBr->getSuccessor(0);
			auto defaultAi = AsmInstruction(defaultBb);
			if (&defaultBb->front() != defaultAi.getLlvmToAsmInstruction())
			{
				return false;
			}

			LOG << root << std::endl;
			LOG << ai << std::endl;
			LOG << "tableAddr = " << tableAddr << std::endl;
			LOG << "tableAddr size = " << tableSize << std::endl;
			LOG << "mulValConst = " << mulValConst->getZExtValue() << std::endl;
			LOG << "idx = " << llvmObjToString(idx) << std::endl;
			LOG << "cond jmp = " << llvmObjToString(condBr) << std::endl;
			LOG << "default label = " << defaultBb->getName().str() << std::endl;
			LOG << "default ai = " << defaultAi.getAddress() << std::endl;
			LOG << "labels:" << std::endl;

			std::vector<AsmInstruction> fullJmpTable;
			std::vector<std::pair<unsigned, AsmInstruction>> jmpTable;
			auto tableItemAddr = tableAddr;
			unsigned cntr = 0;
			while (true)
			{
				auto* ci = _image->getConstantDefault(tableItemAddr);
				if (ci == nullptr)
				{
					break;
				}
				auto targetAi = AsmInstruction(_module, ci->getZExtValue());
				if (targetAi.isInvalid() || targetAi.getFunction() != ai.getFunction())
				{
					break;
				}
				if (tableSize.isDefined() && cntr >= tableSize)
				{
					break;
				}

				LOG << "\t" << targetAi.getAddress();
				fullJmpTable.push_back(targetAi);
				if (targetAi == defaultAi)
				{
					LOG << " -- default label";
				}
				else
				{
					jmpTable.push_back({cntr, targetAi});
				}
				LOG << std::endl;

				tableItemAddr += getTypeByteSizeInBinary(_module, ci->getType());
				++cntr;
			}
			if (jmpTable.empty())
			{
				return false;
			}

			// integration.current.switch.TestEXE (switch-test-msvc-O0.ex)
			//
			std::vector<unsigned> idxs;
			SymbolicTree idxRoot(_RDA, idx);
			idxRoot.simplifyNode(_config);
			if (!_config->getConfig().architecture.isArmOrThumb() // TODO: This can fuck up idx in ARM sgrep-strip.
					&& isa<LoadInst>(idxRoot.value)
					&& cast<LoadInst>(idxRoot.value)->getType()->isIntegerTy()
					&& idxRoot.ops.size() == 1
					&& isa<AddOperator>(idxRoot.ops[0].value)
					&& idxRoot.ops[0].ops.size() == 2
					&& isa<Instruction>(idxRoot.ops[0].ops[0].value)
					&& cast<Instruction>(idxRoot.ops[0].ops[0].value)->getType()->isIntegerTy()
					&& isa<ConstantInt>(idxRoot.ops[0].ops[1].value))
			{
				auto* l = cast<LoadInst>(idxRoot.value);
				auto* it = cast<IntegerType>(l->getType());
				auto* ci = cast<ConstantInt>(idxRoot.ops[0].ops[1].value);
				retdec::utils::Address tableAddr2(ci->getZExtValue());

				// Switch index must not be the table offset.
				// We have to use the original index.
				idx = cast<Instruction>(idxRoot.ops[0].ops[0].value);

				while (true)
				{
					auto* ci = _image->getConstantInt(it, tableAddr2);
					if (ci == nullptr)
					{
						break;
					}
					// A safer condition to end this would be to track constant
					// (second table size) used in comparison in instruction
					// before the cond jmp instruction.
					unsigned idx = ci->getZExtValue();
					if (idx >= fullJmpTable.size())
					{
						break;
					}

					idxs.push_back(idx);
					tableAddr2 += getTypeByteSizeInBinary(_module, ci->getType());
				}
			}
			if (!idxs.empty())
			{
				jmpTable.clear();
				unsigned cntr = 0;
				for (auto i : idxs)
				{
					auto targetAi = fullJmpTable[i];
					if (targetAi != defaultAi)
					{
						jmpTable.push_back({cntr, targetAi});
					}
					++cntr;
				}
			}

			SwitchEntry se;

			se.call = call;
			se.aiSource = ai;
			se.idx = idx;
			se.defaultBb = defaultBb;
			se.jmpTable = jmpTable;

			_toSwitch.push_back(se);

			return true;
		}

		return false;
	}

	return changed;
}

bool ControlFlow::runGenericCondBr(AsmInstruction& ai, llvm::CallInst* call)
{
	bool changed = false;

	auto* op = call->getArgOperand(1);

	if (auto* ci = dyn_cast<ConstantInt>(op))
	{
		if (auto aiTarget = AsmInstruction(_module, ci->getZExtValue()))
		{
			auto* ccf = _config->getLlvmFunction(ci->getZExtValue());
			if (ccf && aiTarget.getAddress() != _config->getFunctionAddress(ccf))
			{
				// TODO -- conditional function call.
//				assert(false);
				return false;
			}

			if (aiTarget.getFunction() != call->getFunction())
			{
				// TODO -- outside this function, but not to an existing
				// function -> create function
				// 1.) if we have AsmInstruction, create function on it.
				// 2.) if we do not have instruction, call unknown on address.
				// create conditional function calls.
//				assert(false);
				return false;
			}

			_toCondBr.insert({call, aiTarget});
			return true;
		}
		else
		{
			// TODO -- have int, but do not have ASM instruction for it
			// -> call unknown on address.
//			assert(false);
			return false;
		}
	}
	else
	{
		// TODO -- call variable
		// 1.) if RDA available, try to compute it.
		// 2.) if not computed, transform to call of variable.
//		assert(false);
//		return false;

		if (!_RDA.wasRun())
		{
			return false;
		}

		SymbolicTree root(_RDA, op);
		root.simplifyNode(_config);

		if (dyn_cast_or_null<ConstantInt>(root.value))
		{
//			assert(false);
		}
		else if (isa<LoadInst>(root.value)
				&& root.ops.size() == 1
				&& isa<ConstantInt>(root.ops[0].value))
		{
			auto* ci1 = dyn_cast<ConstantInt>(root.ops[0].value);
			if (auto* cf1 = _config->getLlvmFunction(ci1->getZExtValue()))
			{
//				transformToCall(ai, call, cf1);
				_toCall.insert({call, ci1->getZExtValue()});

				// control flow function detection
				// in ack.powerpc.gcc-4.5.1.O0.g.elf @ 10000790,
				// there is some code unassociated with any function.
				//
				if (_config->getConfig().architecture.isPpc()
						&& &ai.getFunction()->front() == ai.getBasicBlock()
						&& cf1->isDeclaration())
				{
					auto next = ai.getNext();
					if (next.isValid())
					{
						_toFunctions.insert(next);
					}
				}

				return true;
			}
			else
			{
//				assert(false);
//				auto* ci2 = _image->getConstantDefault(ci1->getZExtValue());
//				auto* cf2 = _config->getLlvmFunction(ci2->getZExtValue());
			}
		}
		else if (isa<LoadInst>(root.value)
				&& root.ops.size() == 1
				&& isa<AddOperator>(root.ops[0].value)
				&& root.ops[0].ops.size() == 2
				&& isa<ConstantInt>(root.ops[0].ops[1].value)
				&& (isa<MulOperator>(root.ops[0].ops[0].value) || isa<ShlOperator>(root.ops[0].ops[0].value))
				&& root.ops[0].ops[0].ops.size() == 2
				&& isa<ConstantInt>(root.ops[0].ops[0].ops[1].value)
				&& isa<Instruction>(root.ops[0].ops[0].ops[0].value)
				&& cast<Instruction>(root.ops[0].ops[0].ops[0].value)->getType()->isIntegerTy())
		{
			auto* tableAddrConst = cast<ConstantInt>(root.ops[0].ops[1].value);
			retdec::utils::Address tableAddr(tableAddrConst->getZExtValue());

			auto* mulValConst = cast<ConstantInt>(root.ops[0].ops[0].ops[1].value); // TODO: or shl const
			auto* idx = cast<Instruction>(root.ops[0].ops[0].ops[0].value);

			BranchInst* condBr = nullptr;
			auto aiNext = ai.getNext();

			for (auto& i : aiNext)
			{
				if (auto* br = dyn_cast<BranchInst>(&i))
				{
					if (br->isUnconditional())
					{
						condBr = br;
						break;
					}
				}
			}
			if (condBr == nullptr)
			{
				return false;
			}
			assert(condBr);

			retdec::utils::Maybe<unsigned> tableSize;
			// TODO: common on ARM, jmp table in code -- we should remove such instructions.
			// pattern is different than in unconditional jump + it is damaged -- true/false
			// constants are computed before here.

			BasicBlock* defaultBb = condBr->getSuccessor(0);
			auto defaultAi = AsmInstruction(defaultBb);
			if (&defaultBb->front() != defaultAi.getLlvmToAsmInstruction())
			{
				return false;
			}

			LOG << root << std::endl;
			LOG << ai << std::endl;
			LOG << "tableAddr = " << tableAddr << std::endl;
			LOG << "tableAddr size = " << tableSize << std::endl;
			LOG << "mulValConst = " << mulValConst->getZExtValue() << std::endl;
			LOG << "idx = " << idx->getName().str() << std::endl;
			LOG << "cond jmp = " << llvmObjToString(condBr) << std::endl;
			LOG << "default label = " << defaultBb->getName().str() << std::endl;
			LOG << "default ai = " << defaultAi.getAddress() << std::endl;
			LOG << "labels:" << std::endl;

			std::vector<std::pair<unsigned, AsmInstruction>> jmpTable;
			auto tableItemAddr = tableAddr;
			unsigned cntr = 0;
			while (true)
			{
				auto* ci = _image->getConstantDefault(tableItemAddr);
				if (ci == nullptr)
				{
					break;
				}
				auto targetAi = AsmInstruction(_module, ci->getZExtValue());
				if (targetAi.isInvalid() || targetAi.getFunction() != ai.getFunction())
				{
					break;
				}
				if (tableSize.isDefined() && cntr >= tableSize)
				{
					break;
				}

				LOG << "\t" << targetAi.getAddress();
				if (targetAi == defaultAi)
				{
					LOG << " -- default label";
				}
				else
				{
					jmpTable.push_back({cntr, targetAi});
				}
				LOG << std::endl;

				tableItemAddr += getTypeByteSizeInBinary(_module, ci->getType());
				++cntr;
			}
			if (jmpTable.empty())
			{
				return false;
			}

			SwitchEntry se;

			se.call = call;
			se.aiSource = ai;
			se.idx = idx;
			se.defaultBb = defaultBb;
			se.jmpTable = jmpTable;

			_toSwitch.push_back(se);

			return true;
		}
	}

	return changed;
}

llvm::ReturnInst* ControlFlow::transformToReturn(
		AsmInstruction& ai,
		llvm::CallInst* call)
{
	if (call == nullptr)
	{
		ai.eraseInstructions();
	}

	auto* term = ai.makeTerminal();
	Value* v = nullptr;
	if (!ai.getFunction()->getReturnType()->isVoidTy())
	{
		v = convertConstantToType(
				_config->getGlobalDummy(),
				ai.getFunction()->getReturnType());
	}
	auto* r = ReturnInst::Create(_module->getContext(), v, term);
	term->eraseFromParent();
	if (call)
	{
		call->eraseFromParent();
	}
	return r;
}

llvm::Value* ControlFlow::getOrMakeFunction(retdec::utils::Address addr)
{
	Value* ret = _config->getLlvmFunction(addr);

	// .plt:00008404 j_printf
	// .plt:00008404                 BX      PC
	// .plt:00008408 ; int printf(const char *format, ...
	//
//	if (_config->getConfig().architecture.isArmOrThumb() && ret == nullptr)
//	{
//		ret = _config->getLlvmFunction(addr + 4);
//	}

	if (ret == nullptr)
	{
		ret = makeFunction(addr);
	}
	return ret;
}

llvm::Value* ControlFlow::makeFunction(retdec::utils::Address addr)
{
	Value* ret = nullptr;

	AsmInstruction aiTarget(_module, addr);
	if (aiTarget.isValid())
	{
		std::string n;
		if (auto* sym = _image->getPreferredSymbol(addr))
		{
			n = sym->getName();
		}

		ret = _irmodif.splitFunctionOn(
				aiTarget.getLlvmToAsmInstruction(),
				aiTarget.getAddress(),
				n).first;
	}
	else
	{
		std::string n;
		if (auto* sym = _image->getPreferredSymbol(addr))
		{
			n = sym->getName();
		}

		if (n.empty())
		{
			auto* ngv = getGlobalVariable(
					_module,
					_config,
					_image,
					DebugFormatProvider::getDebugFormat(_module),
					addr,
					true);
			if (ngv)
			{
				auto* ptrT = llvm::PointerType::get(
						llvm::FunctionType::get(
								getDefaultType(_module),
								false), // isVarArg
							0);
				ret = convertConstantToType(ngv, ptrT);
			}
			else
			{
				ret = _irmodif.addFunctionUnknown(addr).first;
			}
		}
		else
		{
			auto p = _irmodif.addFunction(addr, n);
			p.second->setIsStaticallyLinked();
			ret = p.first;
		}
	}

	return ret;
}

llvm::CallInst* ControlFlow::transformToCall(
		AsmInstruction& ai,
		llvm::CallInst* brCall,
		llvm::Value* called)
{
	std::vector<Value*> args;
	if (auto* f = dyn_cast<Function>(called))
	{
		for (Argument& a : f->args())
		{
			args.push_back(convertConstantToType(
					_config->getGlobalDummy(),
					a.getType()));
		}
	}

	auto* call = CallInst::Create(called, args);

	if (_config->getConfig().architecture.isX86())
	{
		ai.eraseInstructions();
		ai.insertBackSafe(call);
		if (!call->getType()->isVoidTy())
		{
			auto* ro = getReturnObject();
			auto* conv = convertValueToTypeAfter(call, ro->getValueType(), call);
			auto* convI = cast<Instruction>(conv);
			auto* s = new StoreInst(conv, ro);
			s->insertAfter(convI);
		}

		auto* ccf = _config->getConfigFunction(dyn_cast<Function>(called));
		auto* lti = LtiProvider::getLti(_module);
		if (lti && ccf && ccf->isDynamicallyLinked())
		{
			auto p = lti->getPairFunctionFree(ccf->getName());
			if (p.first && p.second)
			{
				auto llvmFnc = p.first;
				auto ltiFnc = p.second;
				if (ltiFnc->getCallConvention() == std::string("stdcall"))
				{
					std::size_t argSz = 0;
					for (auto& a : llvmFnc->args())
					{
						auto defByteSz = getDefaultTypeByteSize(_module);
						auto byteSize = getTypeByteSizeInBinary(_module, a.getType());
						if (byteSize % defByteSz == 0)
						{
							argSz += byteSize;
						}
						else
						{
							argSz += byteSize + (defByteSz - byteSize % defByteSz);
						}
					}

					if (argSz > 0)
					{
						auto* esp = _config->getLlvmRegister("esp");
						if (esp == nullptr)
						{
							esp = _config->getLlvmRegister("rsp");
						}
						assert(esp);
						auto* l = new LoadInst(esp, "", call);
						auto* ci = ConstantInt::get(l->getType(), argSz);
						auto* add = BinaryOperator::CreateAdd(l, ci, "", call);
						auto* s = new StoreInst(add, esp);
						s->insertAfter(call);
					}
				}
			}
		}
	}
	else
	{
		call->insertBefore(brCall);
		brCall->eraseFromParent();
		if (!call->getType()->isVoidTy())
		{
			auto* ro = getReturnObject();
			auto* conv = convertValueToTypeAfter(call, ro->getValueType(), call);
			auto* convI = cast<Instruction>(conv);
			auto* s = new StoreInst(conv, ro);
			s->insertAfter(convI);
		}
	}

	if (_config->getConfig().architecture.isArmOrThumb())
	{
		for (auto& i : ai)
		{
			if (auto* s = dyn_cast<StoreInst>(&i))
			{
				if (s->getPointerOperand()->getName() == "lr")
				{
					s->eraseFromParent();
					break;
				}
			}
		}
	}
	else if (_config->isMipsOrPic32())
	{
		for (auto& i : ai)
		{
			if (auto* s = dyn_cast<StoreInst>(&i))
			{
				if (s->getPointerOperand()->getName() == "ra")
				{
					s->eraseFromParent();
					break;
				}
			}
		}
	}

	return call;
}

llvm::GlobalVariable* ControlFlow::getReturnObject()
{
	static llvm::GlobalVariable* ret = nullptr;
	if (ret)
	{
		return ret;
	}

	if (_config->isMipsOrPic32())
	{
		ret = _config->getLlvmRegister("v0");
	}
	else if (_config->getConfig().architecture.isX86_32())
	{
		ret = _config->getLlvmRegister("eax");
	}
	else if (_config->getConfig().architecture.isX86_64())
	{
		ret = _config->getLlvmRegister("rax");
	}
	else if (_config->getConfig().architecture.isPpc())
	{
		ret = _config->getLlvmRegister("r3");
	}
	else if (_config->getConfig().architecture.isArmOrThumb())
	{
		ret = _config->getLlvmRegister("r0");
	}

	assert(ret);
	return ret;
}

} // namespace bin2llvmir
} // namespace retdec

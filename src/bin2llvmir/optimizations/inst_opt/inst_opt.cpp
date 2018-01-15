/**
* @file src/bin2llvmir/optimizations/inst_opt/inst_opt.cpp
* @brief Instruction optimizations which we want to do ourselves.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cassert>
#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <llvm/IR/Constants.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>

#include "retdec/utils/string.h"
#include "retdec/bin2llvmir/optimizations/inst_opt/inst_opt.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"
#include "retdec/bin2llvmir/utils/defs.h"
#include "retdec/bin2llvmir/utils/instruction.h"
#define debug_enabled false
#include "retdec/llvm-support/utils.h"
#include "retdec/bin2llvmir/utils/type.h"

using namespace retdec::llvm_support;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {

char InstOpt::ID = 0;

static RegisterPass<InstOpt> X(
		"inst-opt",
		"Assembly instruction optimization",
		false, // Only looks at CFG
		false // Analysis Pass
);

InstOpt::InstOpt() :
		ModulePass(ID)
{

}

bool InstOpt::runOnModule(Module& m)
{
	_module = &m;
	_config = ConfigProvider::getConfig(_module);
	removeInstructionNames();
	return run();
}

bool InstOpt::runOnModuleCustom(llvm::Module& m, Config* c)
{
	_module = &m;
	_config = c;
	return run();
}

bool InstOpt::run()
{
	bool changed = false;

	changed |= fixX86RepAnalysis();
	changed |= runGeneralOpts();

	return changed;
}

/**
 * TODO: Instruction names in LLVM IR slow down all the optimizations.
 * The new capstone2llvmir decoder does not generate names, so maybe we can
 * remove this code.
 */
void InstOpt::removeInstructionNames()
{
	for (auto& f : _module->getFunctionList())
	{
		auto it = inst_begin(f);
		auto e = inst_end(f);
		while (it != e)
		{
			Instruction* i = &(*it);
			++it;

			if (i->hasName())
			{
				i->setName(Twine());
			}
		}
	}
}

bool InstOpt::runGeneralOpts()
{
	bool changed = false;

	for (auto& F : _module->getFunctionList())
	{
		for (auto ai = AsmInstruction(&F); ai.isValid(); ai = ai.getNext())
		{
			std::set<Instruction*> toErase;

			for (auto& i : ai)
			{
				if (!isa<BinaryOperator>(i))
				{
					continue;
				}

				auto* op0 = dyn_cast<LoadInst>(i.getOperand(0));
				auto* op1 = dyn_cast<LoadInst>(i.getOperand(1));
				if (!(op0 && op1 && op0->getPointerOperand() == op1->getPointerOperand()))
				{
					continue;
				}
				AsmInstruction op0Asm(op0);
				AsmInstruction op1Asm(op1);
				if ((op0Asm != op1Asm) || (op0Asm != ai))
				{
					continue;
				}

				if (i.getOpcode() == Instruction::Xor)
				{
					i.replaceAllUsesWith(ConstantInt::get(i.getType(), 0));
					toErase.insert(&i);
					op1->replaceAllUsesWith(op0);
					toErase.insert(op1);
					changed = true;
				}
				else if (i.getOpcode() == Instruction::Or
						|| i.getOpcode() == Instruction::And)
				{
					i.replaceAllUsesWith(op0);
					toErase.insert(&i);
					op1->replaceAllUsesWith(op0);
					toErase.insert(op1);
					changed = true;
				}
			}

			for (auto* i : toErase)
			{
				i->eraseFromParent();
				changed = true;
			}
		}
	}

	return changed;
}

bool InstOpt::fixX86RepAnalysis()
{
	if (_config == nullptr || !_config->getConfig().architecture.isX86())
	{
		return false;
	}

	bool changed = false;
	auto& ctx = _module->getContext();

	auto* eax = _config->getLlvmRegister("eax");
	auto* edi = _config->getLlvmRegister("edi");
	auto* ecx = _config->getLlvmRegister("ecx");
	auto* esi = _config->getLlvmRegister("esi");
	auto* zf = _config->getLlvmRegister("zf");
	if (!eax || !edi || !ecx || !esi || !zf)
	{
		LOG << "[ABORT] register not found" << std::endl;
		return false;
	}

	for (auto& F : _module->getFunctionList())
	{
		for (auto ai = AsmInstruction(&F); ai.isValid(); ai = ai.getNext())
		{
			cs_insn* capstoneI = ai.getCapstoneInsn();
			cs_x86* xi = &capstoneI->detail->x86;

			if ((capstoneI->id == X86_INS_STOSB
					|| capstoneI->id == X86_INS_STOSW
					|| capstoneI->id == X86_INS_STOSD)
					&& xi->prefix[0] == X86_PREFIX_REP)
			{
				std::vector<Type*> params = {
						getVoidPointerType(ctx),
						Type::getInt32Ty(ctx),
						getDefaultType(_module)};
				FunctionType* ft = FunctionType::get(
						getVoidPointerType(ctx),
						params,
						false);

				// TODO: Many functions are created in the new decoder, but
				// their types are not set at the moment.
				// Therefore, if memset is created, it does not have the type
				// needed here. Right now, we create new memset variant,
				// but it would be better if decoder created fncs with good
				// types, so it can be used here directly.
				// TODO: the same for all other functions.
				//
				static Function* fnc = nullptr;
				if (fnc == nullptr)
				{
					fnc = _module->getFunction("memset");
					if (fnc == nullptr || fnc->getFunctionType() != ft)
					{
						fnc = Function::Create(
								ft,
								GlobalValue::ExternalLinkage,
								"_memset",
								_module);
					}
				}

				if (fnc == nullptr || fnc->getFunctionType() != ft)
				{
					continue;
				}

				if (!ai.eraseInstructions())
				{
					continue;
				}

				std::vector<Value*> args;
				auto* l0 = ai.insertBackSafe(new LoadInst(edi));
				auto* l1 = ai.insertBackSafe(new LoadInst(eax));
				auto* l2 = ai.insertBackSafe(new LoadInst(ecx));
				args.push_back(convertValueToTypeAfter(l0, params[0], l2));
				args.push_back(convertValueToTypeAfter(l1, params[1], l2));
				args.push_back(convertValueToTypeAfter(l2, params[2], l2));
				auto* call = ai.insertBackSafe(CallInst::Create(fnc, args));
				auto* conv = convertValueToTypeAfter(
						call,
						ecx->getType()->getElementType(),
						call);
				ai.insertBackSafe(new StoreInst(conv, ecx));

				changed = true;
			}
			if ((capstoneI->id == X86_INS_CMPSB
					|| capstoneI->id == X86_INS_CMPSW
					|| capstoneI->id == X86_INS_CMPSD)
					&& xi->prefix[0] == X86_PREFIX_REP)
			{
				std::vector<Type*> params = {
						getCharPointerType(ctx),
						getCharPointerType(ctx),
						getDefaultType(_module)};
				FunctionType* ft = FunctionType::get(
						Type::getInt32Ty(ctx),
						params,
						false);

				static Function* fnc = nullptr;
				if (fnc == nullptr)
				{
					fnc = _module->getFunction("strncmp");
					if (fnc == nullptr || fnc->getFunctionType() != ft)
					{
						fnc = Function::Create(
								ft,
								GlobalValue::ExternalLinkage,
								"_strncmp",
								_module);
					}
				}

				if (fnc == nullptr || fnc->getFunctionType() != ft)
				{
					continue;
				}

				if (!ai.eraseInstructions())
				{
					continue;
				}

				std::vector<Value*> args;
				auto* l0 = ai.insertBackSafe(new LoadInst(esi));
				auto* l1 = ai.insertBackSafe(new LoadInst(edi));
				auto* l2 = ai.insertBackSafe(new LoadInst(ecx));
				args.push_back(convertValueToTypeAfter(l0, params[0], l2));
				args.push_back(convertValueToTypeAfter(l1, params[1], l2));
				args.push_back(convertValueToTypeAfter(l2, params[2], l2));
				auto* call = ai.insertBackSafe(CallInst::Create(fnc, args));
				auto* conv = convertValueToTypeAfter(
						call,
						ecx->getType()->getElementType(),
						call);
				ai.insertBackSafe(new StoreInst(conv, ecx));
				auto* trunc = ai.insertBackSafe(CastInst::CreateTruncOrBitCast(
						conv,
						Type::getInt1Ty(ctx)));
				auto* xorOp = ai.insertBackSafe(BinaryOperator::CreateXor(
						trunc,
						ConstantInt::get(trunc->getType(), 1)));
				ai.insertBackSafe(new StoreInst(xorOp, zf));

				changed = true;
			}
			if ((capstoneI->id == X86_INS_MOVSB
					|| capstoneI->id == X86_INS_MOVSW
					|| capstoneI->id == X86_INS_MOVSD)
					&& xi->prefix[0] == X86_PREFIX_REP)
			{
				std::vector<Type*> params = {
						getVoidPointerType(ctx),
						getVoidPointerType(ctx),
						getDefaultType(_module)};
				FunctionType* ft = FunctionType::get(
						getVoidPointerType(ctx),
						params,
						false);

				static Function* fnc = nullptr;
				if (fnc == nullptr)
				{
					fnc = _module->getFunction("memcpy");
					if (fnc == nullptr || fnc->getFunctionType() != ft)
					{
						fnc = Function::Create(
								ft,
								GlobalValue::ExternalLinkage,
								"_memcpy",
								_module);
					}
				}

				if (fnc == nullptr || fnc->getFunctionType() != ft)
				{
					continue;
				}

				if (!ai.eraseInstructions())
				{
					continue;
				}

				std::vector<Value*> args;
				auto* l0 = ai.insertBackSafe(new LoadInst(edi));
				auto* l1 = ai.insertBackSafe(new LoadInst(esi));
				auto* l2 = ai.insertBackSafe(new LoadInst(ecx));
				args.push_back(convertValueToTypeAfter(l0, params[0], l2));
				args.push_back(convertValueToTypeAfter(l1, params[1], l2));
				args.push_back(convertValueToTypeAfter(l2, params[2], l2));
				auto* call = ai.insertBackSafe(CallInst::Create(fnc, args));
				auto* conv = convertValueToTypeAfter(
						call,
						ecx->getType()->getElementType(),
						call);
				ai.insertBackSafe(new StoreInst(conv, ecx));

				changed = true;
			}
			if ((capstoneI->id == X86_INS_SCASB
					|| capstoneI->id == X86_INS_SCASW
					|| capstoneI->id == X86_INS_SCASD)
					&& xi->prefix[0] == X86_PREFIX_REPNE)
			{
				std::vector<Type*> params = {
						getCharPointerType(ctx)};
				FunctionType* ft = FunctionType::get(
						getDefaultType(_module),
						params,
						false);

				static Function* fnc = nullptr;
				if (fnc == nullptr)
				{
					fnc = _module->getFunction("strlen");
					if (fnc == nullptr || fnc->getFunctionType() != ft)
					{
						fnc = Function::Create(
								ft,
								GlobalValue::ExternalLinkage,
								"_strlen",
								_module);
					}
				}

				if (fnc == nullptr || fnc->getFunctionType() != ft)
				{
					continue;
				}

				if (!ai.eraseInstructions())
				{
					continue;
				}

				std::vector<Value*> args;
				auto* l0 = ai.insertBackSafe(new LoadInst(edi));
				args.push_back(convertValueToTypeAfter(l0, params[0], l0));
				auto* call = ai.insertBackSafe(CallInst::Create(fnc, args));
				auto* mul = ai.insertBackSafe(BinaryOperator::CreateMul(
						call,
						ConstantInt::get(call->getType(), -1, true)));
				auto* add = ai.insertBackSafe(BinaryOperator::CreateSub(
						mul,
						ConstantInt::get(mul->getType(), 2)));
				auto* conv = convertValueToTypeAfter(
						add,
						ecx->getType()->getElementType(),
						add);
				ai.insertBackSafe(new StoreInst(conv, ecx));

				changed = true;
			}
		}
	}

	return changed;
}

} // namespace bin2llvmir
} // namespace retdec

/**
 * @file src/bin2llvmir/optimizations/adapter_methods/adapter_methods.cpp
 * @brief Detection of C++ adapter metods created by compiler.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>
#include <sstream>

#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PatternMatch.h>
#include <llvm/IR/Type.h>
#include <llvm/IR/Value.h>
#include <llvm/Support/raw_ostream.h>

#include "retdec/bin2llvmir/optimizations/adapter_methods/adapter_methods.h"
#include "retdec/bin2llvmir/utils/defs.h"
#define debug_enabled false
#include "retdec/llvm-support/utils.h"

using namespace retdec::llvm_support;
using namespace llvm;
using namespace PatternMatch;

namespace retdec {
namespace bin2llvmir {

char AdapterMethods::ID = 0;

static RegisterPass<AdapterMethods> RegisterPass(
		"adapter-methods",
		"C++ adapter methods optimization",
		false, // Only looks at CFG
		true // Analysis Pass
);

AdapterMethods::AdapterMethods() :
		FunctionPass(ID)
{

}

void AdapterMethods::getAnalysisUsage(AnalysisUsage &AU) const
{
	AU.setPreservesAll();
}

bool AdapterMethods::runOnFunction(Function& F)
{
	config = ConfigProvider::getConfig(F.getParent());

	searchForPattern1(F);
	// more patterns ...

	return false;
}

void AdapterMethods::searchForPattern1(Function& F)
{
	LOG << "\n*** searchForPattern1():\n";

	if (F.getBasicBlockList().size() != 1)
		return;
	BasicBlock &B = *(F.getBasicBlockList().begin());

	enum
	{
		STATE_LOAD,
		STATE_ADDSUB,
		STATE_STORE,
		STATE_CALL,
		STATE_RET,
		STATE_OK,
		STATE_INVALID
	} state = STATE_LOAD;

	LoadInst *load = nullptr;
	CallInst *undef = nullptr;
	Instruction *addSub = nullptr;
	StoreInst *store = nullptr;
	CallInst *call = nullptr;
	StoreInst *endingFlag = nullptr;
	ReturnInst *ret = nullptr;

	for (auto &I : B)
	switch (state)
	{
		case STATE_LOAD:
		{
			if (match(&I, bind_ty<LoadInst>(load)))
			{
				LOG << "\t[load]    :" << llvmObjToString(load) << "\n";
				state = STATE_LOAD;
				break;
			}
			else if (config &&
					match(&I, bind_ty<CallInst>(undef)) &&
					undef->getCalledFunction() &&
					config->getConfig().parameters.isFrontendFunction(undef->getCalledFunction()->getName()))
			{
				LOG << "\t[undef]   :" << llvmObjToString(undef) << "\n";
				state = STATE_LOAD;
				break;
			}
			else if (match(&I, m_Add(m_Value(), m_ConstantInt()))
					|| match(&I, m_Sub(m_Value(), m_ConstantInt())))
			{
				addSub = &I;
				LOG << "\t[add/sub] :" << llvmObjToString(addSub) << "\n";
				state = STATE_STORE;
				break;
			}
			else if (match(&I, bind_ty<CallInst>(call)))
			{
				LOG << "\t[call]    :" << llvmObjToString(call) << "\n";
				state = STATE_RET;
				break;
			}
			else
			{
				state = STATE_INVALID;
				break;
			}
		}
		case STATE_STORE:
		{
			if (match(&I, bind_ty<StoreInst>(store))
					&& store->getValueOperand() == addSub)
			{
				LOG << "\t[store]   :" << llvmObjToString(store) << "\n";
				state = STATE_CALL;
				break;
			}
			else if (match(&I, bind_ty<CallInst>(call)))
			{
				LOG << "\t[call]    :" << llvmObjToString(call)<< "\n";
				state = STATE_RET;
				break;
			}
			else
			{
				state = STATE_INVALID;
				break;
			}
		}
		case STATE_CALL:
		{
			if (match(&I, bind_ty<CallInst>(call)))
			{
				LOG << "\t[call]    :" << llvmObjToString(call)<< "\n";
				state = STATE_RET;
				break;
			}
			else
			{
				state = STATE_INVALID;
				break;
			}
		}
		case STATE_RET:
		{
			if (match(&I, bind_ty<StoreInst>(endingFlag)))
			{
				LOG << "\t[store]   :" << llvmObjToString(endingFlag) << "\n";
				state = STATE_RET;
				break;
			}
			else if (match(&I, bind_ty<ReturnInst>(ret)) && (
					ret->getReturnValue() == call ||
					(ret->getReturnValue() == nullptr &&
					call->getCalledFunction() &&
					call->getCalledFunction()->getReturnType()->isVoidTy())))
			{
				LOG << "\t[ret]     :" << llvmObjToString(ret) << "\n";
				state = STATE_OK;
				break;
			}
			else
			{
				state = STATE_INVALID;
				break;
			}
		}

		default:
		{
			state = STATE_INVALID;
			break;
		}
	}

	if (state == STATE_OK && call->getCalledFunction())
	{
		LOG << "[FOUND] : " << F.getName().str() << " -> "
			<< call->getCalledFunction()->getName().str() << "\n";
		handleAdapter(&F, call->getCalledFunction());
	}
}

void AdapterMethods::handleAdapter(Function* adapter, Function* target)
{
	_adapters[adapter] = target;

	if (config)
	{
		auto* cf = config->getConfigFunction(adapter);
		if (cf)
		{
			LOG << "[APPLIED] : " << adapter->getName().str() << " -> "
				<< target->getName().str() << "\n";
			cf->setWrappedFunctionName(target->getName().str());
		}
	}
}

} // namespace bin2llvmir
} // namespace retdec

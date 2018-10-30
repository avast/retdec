/**
* @file src/bin2llvmir/optimizations/value_protect/value_protect.cpp
* @brief Protect values from LLVM optimization passes.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cassert>

#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/InstIterator.h>

#include "retdec/bin2llvmir/optimizations/value_protect/value_protect.h"
#include "retdec/bin2llvmir/providers/names.h"
#include "retdec/bin2llvmir/utils/ir_modifier.h"
#include "retdec/bin2llvmir/utils/llvm.h"

using namespace retdec::utils;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {

namespace {

/**
 * LLVM: i8 __readNullptrByte()
 */
llvm::Function* getReadNullptrByte(llvm::Module* m)
{
	return Function::Create(
			FunctionType::get(
					Type::getInt8Ty(m->getContext()),
					false),
			GlobalValue::LinkageTypes::ExternalLinkage,
			"__readNullptrByte",
			m);
}

/**
 * LLVM: i16 __readNullptrWord()
 */
llvm::Function* getReadNullptrWord(llvm::Module* m)
{
	return Function::Create(
			FunctionType::get(
					Type::getInt16Ty(m->getContext()),
					false),
			GlobalValue::LinkageTypes::ExternalLinkage,
			"__readNullptrWord",
			m);
}

/**
 * LLVM: i32 __readNullptrDword()
 */
llvm::Function* getReadNullptrDword(llvm::Module* m)
{
	return Function::Create(
			FunctionType::get(
					Type::getInt32Ty(m->getContext()),
					false),
			GlobalValue::LinkageTypes::ExternalLinkage,
			"__readNullptrDword",
			m);
}

/**
 * LLVM: i64 __readNullptrQword()
 */
llvm::Function* getReadNullptrQword(llvm::Module* m)
{
	return Function::Create(
			FunctionType::get(
					Type::getInt64Ty(m->getContext()),
					false),
			GlobalValue::LinkageTypes::ExternalLinkage,
			"__readNullptrQword",
			m);
}

/**
 * LLVM: i8 __readUndefByte()
 */
llvm::Function* getReadUndefByte(llvm::Module* m)
{
	return Function::Create(
			FunctionType::get(
					Type::getInt8Ty(m->getContext()),
					false),
			GlobalValue::LinkageTypes::ExternalLinkage,
			"__readUndefByte",
			m);
}

/**
 * LLVM: i16 __readUndefWord()
 */
llvm::Function* getReadUndefWord(llvm::Module* m)
{
	return Function::Create(
			FunctionType::get(
					Type::getInt16Ty(m->getContext()),
					false),
			GlobalValue::LinkageTypes::ExternalLinkage,
			"__readUndefWord",
			m);
}

/**
 * LLVM: i32 __readUndefDword()
 */
llvm::Function* getReadUndefDword(llvm::Module* m)
{
	return Function::Create(
			FunctionType::get(
					Type::getInt32Ty(m->getContext()),
					false),
			GlobalValue::LinkageTypes::ExternalLinkage,
			"__readUndefDword",
			m);
}

/**
 * LLVM: i64 __readUndefQword()
 */
llvm::Function* getReadUndefQword(llvm::Module* m)
{
	return Function::Create(
			FunctionType::get(
					Type::getInt64Ty(m->getContext()),
					false),
			GlobalValue::LinkageTypes::ExternalLinkage,
			"__readUndefQword",
			m);
}

/**
 * LLVM: void __writeNullptrByte(i8 data)
 */
llvm::Function* getWriteNullptrByte(llvm::Module* m)
{
	return Function::Create(
			FunctionType::get(
					Type::getVoidTy(m->getContext()),
					{Type::getInt8Ty(m->getContext())},
					false),
			GlobalValue::LinkageTypes::ExternalLinkage,
			"__writeNullptrByte",
			m);
}

/**
 * LLVM: void __writeNullptrWord(i16 data)
 */
llvm::Function* getWriteNullptrWord(llvm::Module* m)
{
	return Function::Create(
			FunctionType::get(
					Type::getVoidTy(m->getContext()),
					{Type::getInt16Ty(m->getContext())},
					false),
			GlobalValue::LinkageTypes::ExternalLinkage,
			"__writeNullptrWord",
			m);
}

/**
 * LLVM: void __writeNullptrDword(i32 data)
 */
llvm::Function* getWriteNullptrDword(llvm::Module* m)
{
	return Function::Create(
			FunctionType::get(
					Type::getVoidTy(m->getContext()),
					{Type::getInt32Ty(m->getContext())},
					false),
			GlobalValue::LinkageTypes::ExternalLinkage,
			"__writeNullptrDword",
			m);
}

/**
 * LLVM: void __writeNullptrQword(i64 data)
 */
llvm::Function* getWriteNullptrQword(llvm::Module* m)
{
	return Function::Create(
			FunctionType::get(
					Type::getVoidTy(m->getContext()),
					{Type::getInt64Ty(m->getContext())},
					false),
			GlobalValue::LinkageTypes::ExternalLinkage,
			"__writeNullptrQword",
			m);
}

/**
 * LLVM: void __writeUndefByte(i8 data)
 */
llvm::Function* getWriteUndefByte(llvm::Module* m)
{
	return Function::Create(
			FunctionType::get(
					Type::getVoidTy(m->getContext()),
					{Type::getInt8Ty(m->getContext())},
					false),
			GlobalValue::LinkageTypes::ExternalLinkage,
			"__writeUndefByte",
			m);
}

/**
 * LLVM: void __writeUndefWord(i16 data)
 */
llvm::Function* getWriteUndefWord(llvm::Module* m)
{
	return Function::Create(
			FunctionType::get(
					Type::getVoidTy(m->getContext()),
					{Type::getInt16Ty(m->getContext())},
					false),
			GlobalValue::LinkageTypes::ExternalLinkage,
			"__writeUndefWord",
			m);
}

/**
 * LLVM: void __writeUndefDword(i32 data)
 */
llvm::Function* getWriteUndefDword(llvm::Module* m)
{
	return Function::Create(
			FunctionType::get(
					Type::getVoidTy(m->getContext()),
					{Type::getInt32Ty(m->getContext())},
					false),
			GlobalValue::LinkageTypes::ExternalLinkage,
			"__writeUndefDword",
			m);
}

/**
 * LLVM: void __writeUndefQword(i64 data)
 */
llvm::Function* getWriteUndefQword(llvm::Module* m)
{
	return Function::Create(
			FunctionType::get(
					Type::getVoidTy(m->getContext()),
					{Type::getInt64Ty(m->getContext())},
					false),
			GlobalValue::LinkageTypes::ExternalLinkage,
			"__writeUndefQword",
			m);
}

} // anonymous namespace

char ValueProtect::ID = 0;

std::map<llvm::Type*, llvm::Function*> ValueProtect::_type2fnc;

static RegisterPass<ValueProtect> X(
		"value-protect",
		"Value protection optimization",
		false, // Only looks at CFG
		false // Analysis Pass
);

ValueProtect::ValueProtect() :
		ModulePass(ID)
{

}

bool ValueProtect::runOnModule(Module& M)
{
	_module = &M;
	_config = ConfigProvider::getConfig(_module);
	_abi = AbiProvider::getAbi(_module);
	return run();
}

bool ValueProtect::runOnModuleCustom(llvm::Module& M, Config* c, Abi* abi)
{
	_module = &M;
	_config = c;
	_abi = abi;
	return run();
}

/**
 * @return @c True if module @a _module was modified in any way,
 *         @c false otherwise.
 */
bool ValueProtect::run()
{
	if (_config == nullptr || _abi == nullptr)
	{
		return false;
	}

	bool changed = false;

	changed = _type2fnc.empty() ? protect() : unprotect();

	return changed;
}

bool ValueProtect::protect()
{
	_config->getConfig().parameters.frontendFunctions.insert(
			names::generatedUndefFunctionPrefix);

	bool changed = false;

	changed |= protectStack();
	changed |= protectRegisters();
	changed |= protectLoadStores();

	return changed;
}

bool ValueProtect::protectStack()
{
	bool changed = false;

	for (Function& f : _module->getFunctionList())
	{
		if (f.empty())
		{
			continue;
		}
		auto& bb = f.front();
		for (auto& i : bb)
		{
			// Right now, ww protect all allocas, not only stacks.
			if (auto* a = dyn_cast<AllocaInst>(&i))
			{
				protectValue(a, a->getAllocatedType(), a->getNextNode());
				changed = true;
			}
		}
	}

	return changed;
}

bool ValueProtect::protectRegisters()
{
	bool changed = false;
	const auto& regs = _abi->getRegisters();

	for (Function& F : _module->getFunctionList())
	{
		if (F.empty() || F.front().empty())
		{
			continue;
		}

		// Protect registers only in functions that are NOT called anywhere.
		//
		bool skip = false;
		for (auto uIt = F.user_begin(); uIt != F.user_end(); ++uIt)
		{
			if (isa<CallInst>(*uIt))
			{
				skip = true;
				break;
			}
		}
		if (skip)
		{
			continue;
		}

		Instruction* first = &F.front().front();
		for (auto* r : regs)
		{
			protectValue(r, r->getValueType(), first);
			changed = true;
		}
	}

	return changed;
}

void ValueProtect::protectValue(
		llvm::Value* val,
		llvm::Type* t,
		llvm::Instruction* before)
{
	Function* fnc = getOrCreateFunction(t);
	auto* c = CallInst::Create(fnc);
	c->insertBefore(before);
	auto* s = new StoreInst(c, val);
	s->insertAfter(c);
}

/**
 * Replace loads/stores from/to undef/nullptr values by special intrinsic
 * functions.
 * These loads and stores would be recognized by LLVM optimization passes and
 * they would cause "abort() // UNREACHABLE" pattern in the output C.
 */
bool ValueProtect::protectLoadStores()
{
	bool changed = false;
	auto& c = _config;

	for (Function& f : *_module)
	for (auto it = inst_begin(&f), eIt = inst_end(&f); it != eIt;)
	{
		Instruction* insn = &*it;
		++it;

		if (auto* l = dyn_cast<LoadInst>(insn))
		{
			Function* replacement = nullptr;

			auto* ptr = llvm_utils::skipCasts(l->getPointerOperand());
			if (isa<UndefValue>(ptr))
			{
				if (l->getType()->isIntegerTy(8))
				{
					replacement = c->getIntrinsicFunction(getReadUndefByte);
				}
				else if (l->getType()->isIntegerTy(16))
				{
					replacement = c->getIntrinsicFunction(getReadUndefWord);
				}
				else if (l->getType()->isIntegerTy(32))
				{
					replacement = c->getIntrinsicFunction(getReadUndefDword);
				}
				else if (l->getType()->isIntegerTy(64))
				{
					replacement = c->getIntrinsicFunction(getReadUndefQword);
				}
			}
			else if (isa<ConstantPointerNull>(ptr))
			{
				if (l->getType()->isIntegerTy(8))
				{
					replacement = c->getIntrinsicFunction(getReadNullptrByte);
				}
				else if (l->getType()->isIntegerTy(16))
				{
					replacement = c->getIntrinsicFunction(getReadNullptrWord);
				}
				else if (l->getType()->isIntegerTy(32))
				{
					replacement = c->getIntrinsicFunction(getReadNullptrDword);
				}
				else if (l->getType()->isIntegerTy(64))
				{
					replacement = c->getIntrinsicFunction(getReadNullptrQword);
				}
			}

			if (replacement == nullptr)
			{
				continue;
			}
			if (replacement->arg_size() != 0) // expecting zero args
			{
				continue;
			}

			auto* call = CallInst::Create(replacement, "", l);
			auto* conv = IrModifier::convertValueToType(call, l->getType(), l);

			conv->takeName(l);
			l->replaceAllUsesWith(conv);
			l->eraseFromParent();

			changed = true;
		}
		else if (StoreInst* s = dyn_cast<StoreInst>(insn))
		{
			Function* replacement = nullptr;

			auto* ptr = llvm_utils::skipCasts(s->getPointerOperand());
			if (isa<UndefValue>(ptr))
			{
				if (s->getValueOperand()->getType()->isIntegerTy(8))
				{
					replacement = c->getIntrinsicFunction(getWriteUndefByte);
				}
				else if (s->getValueOperand()->getType()->isIntegerTy(16))
				{
					replacement = c->getIntrinsicFunction(getWriteUndefWord);
				}
				else if (s->getValueOperand()->getType()->isIntegerTy(32))
				{
					replacement = c->getIntrinsicFunction(getWriteUndefDword);
				}
				else if (s->getValueOperand()->getType()->isIntegerTy(64))
				{
					replacement = c->getIntrinsicFunction(getWriteUndefQword);
				}
			}
			else if (isa<ConstantPointerNull>(ptr))
			{
				if (s->getValueOperand()->getType()->isIntegerTy(8))
				{
					replacement = c->getIntrinsicFunction(getWriteNullptrByte);
				}
				else if (s->getValueOperand()->getType()->isIntegerTy(16))
				{
					replacement = c->getIntrinsicFunction(getWriteNullptrWord);
				}
				else if (s->getValueOperand()->getType()->isIntegerTy(32))
				{
					replacement = c->getIntrinsicFunction(getWriteNullptrDword);
				}
				else if (s->getValueOperand()->getType()->isIntegerTy(64))
				{
					replacement = c->getIntrinsicFunction(getWriteNullptrQword);
				}
			}

			if (replacement == nullptr)
			{
				continue;
			}
			if (replacement->arg_size() != 1) // expecting one arg
			{
				continue;
			}

			Argument& arg = *replacement->arg_begin();
			auto* val = s->getValueOperand();
			val = IrModifier::convertValueToType(val, arg.getType(), s);

			CallInst::Create(replacement, {val}, "", s);

			s->eraseFromParent();

			changed = true;
		}
	}

	return changed;
}

llvm::Function* ValueProtect::getOrCreateFunction(llvm::Type* t)
{
	auto fIt = _type2fnc.find(t);
	return fIt != _type2fnc.end() ? fIt->second : createFunction(t);
}

llvm::Function* ValueProtect::createFunction(llvm::Type* t)
{
	FunctionType* ft = FunctionType::get(t, false);
	auto* fnc = Function::Create(
			ft,
			GlobalValue::ExternalLinkage,
			names::generateFunctionNameUndef(_type2fnc.size()),
			_module);
	_type2fnc[t] = fnc;

	return fnc;
}

/**
 * TODO: Only partial removal, see:
 * https://github.com/avast-tl/retdec/issues/301
 */
bool ValueProtect::unprotect()
{
	bool changed = false;

	for (auto& p : _type2fnc)
	{
		auto* fnc = p.second;

		for (auto uIt = fnc->user_begin(); uIt != fnc->user_end();)
		{
			auto* u = *uIt;
			++uIt;

			for (auto uuIt = u->user_begin(); uuIt != u->user_end();)
			{
				auto* uu = *uuIt;
				++uuIt;

				if (auto* s = dyn_cast<StoreInst>(uu))
				{
					s->eraseFromParent();
					changed = true;
				}
			}

			Instruction* i = cast<Instruction>(u);
			if (i->user_empty())
			{
				i->eraseFromParent();
				changed = true;
			}
		}

		if (fnc->user_empty())
		{
			fnc->eraseFromParent();
			changed = true;
		}
	}

	_type2fnc.clear();
	return changed;
}

} // namespace bin2llvmir
} // namespace retdec

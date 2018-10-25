/**
 * @file src/bin2llvmir/optimizations/x86_addr_spaces/x86_addr_spaces.cpp
 * @brief Optimize a single x86 address spaces instruction.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#include <llvm/IR/Instructions.h>
#include <llvm/IR/Constants.h>

#include "retdec/bin2llvmir/optimizations/x86_addr_spaces/x86_addr_spaces.h"
#include "retdec/bin2llvmir/providers/abi/abi.h"
#include "retdec/bin2llvmir/utils/ir_modifier.h"
#include "retdec/bin2llvmir/utils/llvm.h"
#include "retdec/capstone2llvmir/x86/x86_defs.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {
namespace x86_addr_spaces {

namespace {

/**
 * MSDN: unsigned char __readfsbyte(unsigned long Offset);
 * LLVM: i8 __readfsbyte(<default_type> offset)
 */
llvm::Function* getReadFsByte(llvm::Module* m)
{
	return Function::Create(
			FunctionType::get(
					Type::getInt8Ty(m->getContext()),
					{Abi::getDefaultType(m)},
					false),
			GlobalValue::LinkageTypes::ExternalLinkage,
			"__readfsbyte",
			m);
}

/**
 * MSDN: unsigned short __readfsword(unsigned long Offset);
 * LLVM: i16 __readfsword(<default_type> offset)
 */
llvm::Function* getReadFsWord(llvm::Module* m)
{
	return Function::Create(
			FunctionType::get(
					Type::getInt16Ty(m->getContext()),
					{Abi::getDefaultType(m)},
					false),
			GlobalValue::LinkageTypes::ExternalLinkage,
			"__readfsword",
			m);
}

/**
 * MSDN: unsigned long __readfsdword(unsigned long Offset);
 * LLVM: i32 __readfsdword(<default_type> offset)
 */
llvm::Function* getReadFsDword(llvm::Module* m)
{
	return Function::Create(
			FunctionType::get(
					Type::getInt32Ty(m->getContext()),
					{Abi::getDefaultType(m)},
					false),
			GlobalValue::LinkageTypes::ExternalLinkage,
			"__readfsdword",
			m);
}

/**
 * MSDN: unsigned __int64 __readfsqword(unsigned long Offset);
 * LLVM: i64 __readfsdword(<default_type> offset)
 */
llvm::Function* getReadFsQword(llvm::Module* m)
{
	return Function::Create(
			FunctionType::get(
					Type::getInt64Ty(m->getContext()),
					{Abi::getDefaultType(m)},
					false),
			GlobalValue::LinkageTypes::ExternalLinkage,
			"__readfsqword",
			m);
}

/**
 * MSDN: void __writefsbyte(unsigned long Offset, unsigned char Data);
 * LLVM: void __writefsbyte(<default_type> offset, i8 data)
 */
llvm::Function* getWriteFsByte(llvm::Module* m)
{
	return Function::Create(
			FunctionType::get(
					Type::getVoidTy(m->getContext()),
					{Abi::getDefaultType(m), Type::getInt8Ty(m->getContext())},
					false),
			GlobalValue::LinkageTypes::ExternalLinkage,
			"__writefsbyte",
			m);
}

/**
 * MSDN: void __writefsword(unsigned long Offset, unsigned short Data);
 * LLVM: void __writefsword(<default_type> offset, i16 data)
 */
llvm::Function* getWriteFsWord(llvm::Module* m)
{
	return Function::Create(
			FunctionType::get(
					Type::getVoidTy(m->getContext()),
					{Abi::getDefaultType(m), Type::getInt16Ty(m->getContext())},
					false),
			GlobalValue::LinkageTypes::ExternalLinkage,
			"__writefsword",
			m);
}

/**
 * MSDN: void __writefsdword(unsigned long Offset, unsigned long Data);
 * LLVM: void __writefsdword(<default_type> offset, i32 data)
 */
llvm::Function* getWriteFsDword(llvm::Module* m)
{
	return Function::Create(
			FunctionType::get(
					Type::getVoidTy(m->getContext()),
					{Abi::getDefaultType(m), Type::getInt32Ty(m->getContext())},
					false),
			GlobalValue::LinkageTypes::ExternalLinkage,
			"__writefsdword",
			m);
}

/**
 * MSDN: void __writefsqword(unsigned long Offset, unsigned __int64 Data);
 * LLVM: void __writefsqword(<default_type> offset, i64 data)
 */
llvm::Function* getWriteFsQword(llvm::Module* m)
{
	return Function::Create(
			FunctionType::get(
					Type::getVoidTy(m->getContext()),
					{Abi::getDefaultType(m), Type::getInt64Ty(m->getContext())},
					false),
			GlobalValue::LinkageTypes::ExternalLinkage,
			"__writefsqword",
			m);
}

/**
 * MSDN: unsigned char __readgsbyte(unsigned long Offset);
 * LLVM: i8 __readgsbyte(<default_type> offset)
 */
llvm::Function* getReadGsByte(llvm::Module* m)
{
	return Function::Create(
			FunctionType::get(
					Type::getInt8Ty(m->getContext()),
					{Abi::getDefaultType(m)},
					false),
			GlobalValue::LinkageTypes::ExternalLinkage,
			"__readgsbyte",
			m);
}

/**
 * MSDN: unsigned short __readgsword(unsigned long Offset);
 * LLVM: i16 __readgsword(<default_type> offset)
 */
llvm::Function* getReadGsWord(llvm::Module* m)
{
	return Function::Create(
			FunctionType::get(
					Type::getInt16Ty(m->getContext()),
					{Abi::getDefaultType(m)},
					false),
			GlobalValue::LinkageTypes::ExternalLinkage,
			"__readgsword",
			m);
}

/**
 * MSDN: unsigned long __readgsdword(unsigned long Offset);
 * LLVM: i32 __readgsdword(<default_type> offset)
 */
llvm::Function* getReadGsDword(llvm::Module* m)
{
	return Function::Create(
			FunctionType::get(
					Type::getInt32Ty(m->getContext()),
					{Abi::getDefaultType(m)},
					false),
			GlobalValue::LinkageTypes::ExternalLinkage,
			"__readgsdword",
			m);
}

/**
 * MSDN: unsigned __int64 __readgsqword(unsigned long Offset);
 * LLVM: i64 __readgsqword(<default_type> offset)
 */
llvm::Function* getReadGsQword(llvm::Module* m)
{
	return Function::Create(
			FunctionType::get(
					Type::getInt64Ty(m->getContext()),
					{Abi::getDefaultType(m)},
					false),
			GlobalValue::LinkageTypes::ExternalLinkage,
			"__readgsqword",
			m);
}

/**
 * MSDN: void __writegsbyte(unsigned long Offset, unsigned char Data);
 * LLVM: void __writegsbyte(<default_type> offset, i8 data)
 */
llvm::Function* getWriteGsByte(llvm::Module* m)
{
	return Function::Create(
			FunctionType::get(
					Type::getVoidTy(m->getContext()),
					{Abi::getDefaultType(m), Type::getInt8Ty(m->getContext())},
					false),
			GlobalValue::LinkageTypes::ExternalLinkage,
			"__writegsbyte",
			m);
}

/**
 * MSDN: void __writegsword(unsigned long Offset, unsigned short Data);
 * LLVM: void __writegsword(<default_type> offset, i16 data)
 */
llvm::Function* getWriteGsWord(llvm::Module* m)
{
	return Function::Create(
			FunctionType::get(
					Type::getVoidTy(m->getContext()),
					{Abi::getDefaultType(m), Type::getInt16Ty(m->getContext())},
					false),
			GlobalValue::LinkageTypes::ExternalLinkage,
			"__writegsword",
			m);
}

/**
 * MSDN: void __writegsdword(unsigned long Offset, unsigned long Data);
 * LLVM: void __writegsdword(<default_type> offset, i32 data)
 */
llvm::Function* getWriteGsDword(llvm::Module* m)
{
	return Function::Create(
			FunctionType::get(
					Type::getVoidTy(m->getContext()),
					{Abi::getDefaultType(m), Type::getInt32Ty(m->getContext())},
					false),
			GlobalValue::LinkageTypes::ExternalLinkage,
			"__writegsdword",
			m);
}

/**
 * MSDN: void __writegsqword(unsigned long Offset, unsigned __int64 Data);
 * LLVM: void __writegsqword(<default_type> offset, i64 data)
 */
llvm::Function* getWriteGsQword(llvm::Module* m)
{
	return Function::Create(
			FunctionType::get(
					Type::getVoidTy(m->getContext()),
					{Abi::getDefaultType(m), Type::getInt64Ty(m->getContext())},
					false),
			GlobalValue::LinkageTypes::ExternalLinkage,
			"__writegsqword",
			m);
}

llvm::Instruction* optimizeLoad(llvm::LoadInst* load, Config* c)
{
	unsigned addrSpace = load->getPointerAddressSpace();

	Function* replacement = nullptr;

	if (addrSpace == static_cast<unsigned>(x86_addr_space::FS))
	{
		if (load->getType()->isIntegerTy(8))
		{
			replacement = c->getIntrinsicFunction(getReadFsByte);
		}
		else if (load->getType()->isIntegerTy(16))
		{
			replacement = c->getIntrinsicFunction(getReadFsWord);
		}
		else if (load->getType()->isIntegerTy(32))
		{
			replacement = c->getIntrinsicFunction(getReadFsDword);
		}
		else if (load->getType()->isIntegerTy(64))
		{
			replacement = c->getIntrinsicFunction(getReadFsQword);
		}
	}
	else if (addrSpace == static_cast<unsigned>(x86_addr_space::GS))
	{
		if (load->getType()->isIntegerTy(8))
		{
			replacement = c->getIntrinsicFunction(getReadGsByte);
		}
		else if (load->getType()->isIntegerTy(16))
		{
			replacement = c->getIntrinsicFunction(getReadGsWord);
		}
		else if (load->getType()->isIntegerTy(32))
		{
			replacement = c->getIntrinsicFunction(getReadGsDword);
		}
		else if (load->getType()->isIntegerTy(64))
		{
			replacement = c->getIntrinsicFunction(getReadGsQword);
		}
	}

	if (replacement == nullptr)
	{
		return nullptr;
	}
	if (replacement->arg_size() != 1) // expecting one arg
	{
		return nullptr;
	}

	Argument& arg = *replacement->arg_begin();
	auto* ptr = llvm_utils::skipCasts(load->getPointerOperand());
	ptr = IrModifier::convertValueToType(ptr, arg.getType(), load);

	auto* call = CallInst::Create(replacement, {ptr}, "", load);
	auto* conv = IrModifier::convertValueToType(call, load->getType(), load);

	conv->takeName(load);
	load->replaceAllUsesWith(conv);
	load->eraseFromParent();

	return call;
}

llvm::Instruction* optimizeStore(llvm::StoreInst* store, Config* c)
{
	unsigned addrSpace = store->getPointerAddressSpace();

	Function* replacement = nullptr;

	if (addrSpace == static_cast<unsigned>(x86_addr_space::FS))
	{
		if (store->getValueOperand()->getType()->isIntegerTy(8))
		{
			replacement = c->getIntrinsicFunction(getWriteFsByte);
		}
		else if (store->getValueOperand()->getType()->isIntegerTy(16))
		{
			replacement = c->getIntrinsicFunction(getWriteFsWord);
		}
		else if (store->getValueOperand()->getType()->isIntegerTy(32))
		{
			replacement = c->getIntrinsicFunction(getWriteFsDword);
		}
		else if (store->getValueOperand()->getType()->isIntegerTy(64))
		{
			replacement = c->getIntrinsicFunction(getWriteFsQword);
		}
	}
	else if (addrSpace == static_cast<unsigned>(x86_addr_space::GS))
	{
		if (store->getValueOperand()->getType()->isIntegerTy(8))
		{
			replacement = c->getIntrinsicFunction(getWriteGsByte);
		}
		else if (store->getValueOperand()->getType()->isIntegerTy(16))
		{
			replacement = c->getIntrinsicFunction(getWriteGsWord);
		}
		else if (store->getValueOperand()->getType()->isIntegerTy(32))
		{
			replacement = c->getIntrinsicFunction(getWriteGsDword);
		}
		else if (store->getValueOperand()->getType()->isIntegerTy(64))
		{
			replacement = c->getIntrinsicFunction(getWriteGsQword);
		}
	}

	if (replacement == nullptr)
	{
		return nullptr;
	}
	if (replacement->arg_size() != 2) // expecting 2 args
	{
		return nullptr;
	}

	auto ait = replacement->arg_begin();
	Argument& arg1 = *ait++;
	auto* ptr = llvm_utils::skipCasts(store->getPointerOperand());
	ptr = IrModifier::convertValueToType(ptr, arg1.getType(), store);

	Argument& arg2 = *ait;
	auto* val = store->getValueOperand();
	val = IrModifier::convertValueToType(val, arg2.getType(), store);

	auto* call = CallInst::Create(replacement, {ptr, val}, "", store);

	store->eraseFromParent();

	return call;
}

} // anonymous namespace

llvm::Instruction* optimize(llvm::Instruction* insn, Config* config)
{
	if (LoadInst* l = dyn_cast<LoadInst>(insn))
	{
		return optimizeLoad(l, config);
	}
	else if (StoreInst* s = dyn_cast<StoreInst>(insn))
	{
		return optimizeStore(s, config);
	}
	else
	{
		return nullptr;
	}
}

llvm::Instruction* optimize(llvm::Instruction* insn, bool isX86, Config* config)
{
	return isX86 ? optimize(insn, config) : nullptr;
}

} // namespace x86_addr_spaces
} // namespace bin2llvmir
} // namespace retdec

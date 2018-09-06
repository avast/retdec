/**
* @file include/retdec/bin2llvmir/optimizations/stack_pointer_ops/stack_pointer_ops.h
* @brief Remove the remaining stack pointer operations.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_STACK_POINTER_OPS_STACK_POINTER_OPS_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_STACK_POINTER_OPS_STACK_POINTER_OPS_H

#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include "retdec/bin2llvmir/providers/abi/abi.h"

namespace retdec {
namespace bin2llvmir {

class StackPointerOpsRemove : public llvm::ModulePass
{
	public:
		static char ID;
		StackPointerOpsRemove();
		virtual bool runOnModule(llvm::Module& m) override;
		bool runOnModuleCustom(llvm::Module& m, Abi* a);

	private:
		bool run();
		bool removeStackPointerStores();
		bool removePreservationStores();

	private:
		llvm::Module* _module = nullptr;
		Abi* _abi = nullptr;
};

} // namespace bin2llvmir
} // namespace retdec

#endif

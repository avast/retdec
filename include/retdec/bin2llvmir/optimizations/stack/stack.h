/**
* @file include/retdec/bin2llvmir/optimizations/stack/stack.h
* @brief Reconstruct stack.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_STACK_STACK_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_STACK_STACK_H

#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include "retdec/bin2llvmir/analyses/symbolic_tree.h"
#include "retdec/bin2llvmir/providers/abi/abi.h"
#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/providers/debugformat.h"

namespace retdec {
namespace bin2llvmir {

class StackAnalysis : public llvm::ModulePass
{
	public:
		static char ID;
		StackAnalysis();
		virtual bool runOnModule(llvm::Module& m) override;
		bool runOnModuleCustom(
				llvm::Module& m,
				Config* c,
				Abi* abi,
				DebugFormat* dbgf = nullptr);

	private:
		bool run();
		void handleInstruction(
				ReachingDefinitionsAnalysis& RDA,
				llvm::Instruction* inst,
				llvm::Value* val,
				llvm::Type* type,
				std::map<llvm::Value*, llvm::Value*>& val2val);
		retdec::config::Object* getDebugStackVariable(
				llvm::Function* fnc,
				SymbolicTree& root);

	private:
		llvm::Module* _module = nullptr;
		Config* _config = nullptr;
		Abi* _abi = nullptr;
		DebugFormat* _dbgf = nullptr;
};

} // namespace bin2llvmir
} // namespace retdec

#endif

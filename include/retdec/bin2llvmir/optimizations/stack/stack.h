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
#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/providers/debugformat.h"

namespace retdec {
namespace bin2llvmir {

/**
 * TODO:
 * At the moment, this is very similar to ConstantsAnalysis -> merge together.
 */
class StackAnalysis : public llvm::ModulePass
{
	public:
		static char ID;
		StackAnalysis();
		virtual bool runOnModule(llvm::Module& m) override;
		bool runOnModuleCustom(
				llvm::Module& m,
				Config* c,
				DebugFormat* dbgf = nullptr);

	private:
		struct ReplaceItem
		{
			llvm::Instruction* inst;
			llvm::Value* from;
			llvm::AllocaInst* to;
		};

	private:
		bool run();
		bool runOnFunction(ReachingDefinitionsAnalysis& RDA, llvm::Function* f);
		bool handleInstruction(
				ReachingDefinitionsAnalysis& RDA,
				llvm::Instruction* inst,
				llvm::Value* val,
				llvm::Type* type,
				std::list<ReplaceItem>& _replaceItems,
				std::map<llvm::Value*, llvm::Value*>& val2val);
		retdec::config::Object* getDebugStackVariable(
				llvm::Function* fnc,
				SymbolicTree& root);

	private:
		llvm::Module* _module = nullptr;
		Config* _config = nullptr;
		DebugFormat* _dbgf = nullptr;
};

} // namespace bin2llvmir
} // namespace retdec

#endif

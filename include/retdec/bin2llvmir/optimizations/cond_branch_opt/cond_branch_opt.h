/**
* @file include/retdec/bin2llvmir/optimizations/cond_branch_opt/cond_branch_opt.h
* @brief Conditional branch optimization.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_COND_BRANCH_OPT_COND_BRANCH_OPT_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_COND_BRANCH_OPT_COND_BRANCH_OPT_H

#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include "retdec/bin2llvmir/providers/abi/abi.h"
#include "retdec/bin2llvmir/providers/config.h"

namespace retdec {
namespace bin2llvmir {

/**
 * InstructionOptimizer pass (-inst-opt) *MUST* run before this pass.
 * We need the following transformations to match more patterns:
 *   - xor i1 x, y  ->  icmp ne i1 x, y
 *   - and i1 x, y  ->  icmp eq i1 x, y
 */
class CondBranchOpt : public llvm::ModulePass
{
	public:
		static char ID;
		CondBranchOpt();
		virtual bool runOnModule(llvm::Module& m) override;
		bool runOnModuleCustom(llvm::Module& m, Config* c, Abi* abi);

	private:
		bool run();
		bool runOnInstruction(
				ReachingDefinitionsAnalysis& RDA,
				llvm::Instruction& i);

		bool transformConditionSub(
				llvm::BranchInst* br,
				llvm::Value* testedVal,
				llvm::Value* subVal,
				llvm::Instruction* binOp,
				llvm::CmpInst::Predicate predicate);

	private:
		llvm::Module* _module = nullptr;
		Config* _config = nullptr;
		Abi* _abi = nullptr;
};

} // namespace bin2llvmir
} // namespace retdec

#endif

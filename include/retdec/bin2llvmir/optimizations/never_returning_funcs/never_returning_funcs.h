/**
* @file include/retdec/bin2llvmir/optimizations/never_returning_funcs/never_returning_funcs.h
* @brief Adds unreachable instruction after function that never returns.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_NEVER_RETURNING_FUNCS_NEVER_RETURNING_FUNCS_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_NEVER_RETURNING_FUNCS_NEVER_RETURNING_FUNCS_H

#include <llvm/IR/InstVisitor.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Pass.h>

#include "retdec/bin2llvmir/utils/defs.h"

namespace retdec {
namespace bin2llvmir {

/**
* @brief Adds unreachable instruction after functions that never return.
*
* This optimization also removes instructions that are in basic block after
* function that never returns.
*/
class NeverReturningFuncs: public llvm::FunctionPass,
		private llvm::InstVisitor<NeverReturningFuncs> {
public:
	/// Set of terminator instructions.
	using TerminatorInstSet = std::set<llvm::TerminatorInst *>;

public:
	static char ID;
	NeverReturningFuncs();
	virtual bool doInitialization(llvm::Module &module) override;
	virtual bool doFinalization(llvm::Module &module) override;
	virtual bool runOnFunction(llvm::Function &func) override;
	bool runOnFunctionCustom(llvm::Function &func);

	static const char *getName() { return NAME; }

private:
	friend class llvm::InstVisitor<NeverReturningFuncs>;

	bool run(llvm::Function &func);
	void visitCallInst(llvm::CallInst &callInst);

	void initBeforeRun();
	void initFuncNeverReturnsMap();
	void deinitFuncNeverReturnsMap();
	void addInstsThatWillBeRemoved(llvm::Instruction &inst);
	void replaceTerminatorInstsWithUnreachableInst(
			const TerminatorInstSet &toReplace);
	bool neverReturns(const llvm::Function *func);

private:
	/// Name of the optimization.
	static const char *NAME;

	/// Mapping of functions that never return.
	static StringVecFuncMap funcNeverReturnsMap;

	/// Optimized module.
	llvm::Module *module;

	/// Set of instruction to remove.
	InstSet instsToRemove;

	/// Set of terminator instructions to replace.
	TerminatorInstSet instsToReplace;
};

} // namespace bin2llvmir
} // namespace retdec

#endif

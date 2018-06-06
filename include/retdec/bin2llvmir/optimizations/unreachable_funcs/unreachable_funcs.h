/**
* @file include/retdec/bin2llvmir/optimizations/unreachable_funcs/unreachable_funcs.h
* @brief Removes unreachable functions from main.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_UNREACHABLE_FUNCS_UNREACHABLE_FUNCS_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_UNREACHABLE_FUNCS_UNREACHABLE_FUNCS_H

#include <llvm/Analysis/CallGraph.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include "retdec/bin2llvmir/providers/config.h"

namespace retdec {
namespace bin2llvmir {

/**
* @brief Removes unreachable functions from main.
*
* @code
* void func1() { ... } <- Not calls func2.
* void func2() { ... } <- Unreachable function. Can be optimized.
* int main() {
*   func1();
* }
* @endcode
*/
class UnreachableFuncs: public llvm::ModulePass
{
	public:
		static char ID;
		UnreachableFuncs();
		virtual void getAnalysisUsage(llvm::AnalysisUsage& au) const override;
		virtual bool runOnModule(llvm::Module& m) override;
		bool runOnModuleCustom(llvm::Module& m, Config* c);

	private:
		bool run();
		void getFuncsThatCannotBeOptimized(
				std::set<llvm::Function*>& funcsThatCannotBeOptimized);
		void removeFuncsThatCanBeOptimized(
				const std::set<llvm::Function*>& funcsThatCannotBeOptimized);

	private:
		llvm::Module* module = nullptr;
		Config* config = nullptr;
		llvm::CallGraph* callGraph = nullptr;
		llvm::Function *mainFunc = nullptr;
		unsigned NumFuncsRemoved = 0;
};

} // namespace bin2llvmir
} // namespace retdec

#endif

/**
* @file include/retdec/bin2llvmir/optimizations/idioms_libgcc/idioms_libgcc.h
* @brief Idioms produced by libgcc.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_IDIOMS_LIBGCC_IDIOMS_LIBGCC_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_IDIOMS_LIBGCC_IDIOMS_LIBGCC_H

#include <functional>
#include <memory>

#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include "retdec/bin2llvmir/providers/config.h"

namespace retdec {
namespace bin2llvmir {

class IdiomsLibgccImpl;

class IdiomsLibgcc : public llvm::ModulePass
{
	public:
		using Fnc2Action = std::vector<std::pair<std::string, std::function<void(llvm::CallInst*)>>>;

	public:
		static char ID;
		IdiomsLibgcc();
		virtual void getAnalysisUsage(llvm::AnalysisUsage &AU) const override;
		virtual bool runOnModule(llvm::Module& M) override;

		static bool checkFunctionToActionMap(const Fnc2Action& fnc2action);

	private:
		bool testArchAndInitialize();
		bool handleInstructions();
		bool handleInstruction(llvm::Instruction* inst);
		void localize();

	private:
		std::unique_ptr<IdiomsLibgccImpl> _impl;
		llvm::Module* _module = nullptr;
		Config* _config = nullptr;

		Fnc2Action _fnc2action;
};

} // namespace bin2llvmir
} // namespace retdec

#endif

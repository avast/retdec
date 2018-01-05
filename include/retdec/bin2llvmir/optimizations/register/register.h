/**
* @file include/retdec/bin2llvmir/optimizations/register/register.h
* @brief Solve register pseudo functions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_REGISTER_REGISTER_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_REGISTER_REGISTER_H

#include <map>

#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include "retdec/bin2llvmir/analyses/symbolic_tree.h"
#include "retdec/bin2llvmir/providers/config.h"

namespace retdec {
namespace bin2llvmir {

class RegisterAnalysis : public llvm::ModulePass
{
	public:
		static char ID;
		RegisterAnalysis();
		virtual bool runOnModule(llvm::Module& m) override;
		bool runOnModuleCustom(
				llvm::Module& m,
				Config* c);

	private:
		bool run();
		bool x86FpuAnalysis();
		bool x86FpuAnalysisBb(
				retdec::utils::NonIterableSet<llvm::BasicBlock*>& seenBbs,
				llvm::BasicBlock* bb,
				int topVal);

		bool isRegisterStoreFunction(llvm::Function* f);
		bool isRegisterLoadFunction(llvm::Function* f);
		llvm::CallInst* isRegisterStoreFunctionCall(llvm::Value* val);
		llvm::CallInst* isRegisterLoadFunctionCall(llvm::Value* val);
		std::string getRegisterClass(llvm::Function* f);
		llvm::GlobalVariable* getLlvmRegister(
				const std::string& regClass,
				unsigned regNum);

	private:
		llvm::Module* _module = nullptr;
		Config* _config = nullptr;
		llvm::GlobalVariable* top = nullptr;

		const std::string _regStoreFncName = "__frontend_reg_store";
		const std::string _regLoadFncName = "__frontend_reg_load";
};

} // namespace bin2llvmir
} // namespace retdec

#endif

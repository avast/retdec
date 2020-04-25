/**
* @file include/retdec/bin2llvmir/optimizations/constants/constants.h
* @brief Composite type reconstruction analysis.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_CONSTANTS_CONSTANTS_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_CONSTANTS_CONSTANTS_H

#include <set>
#include <unordered_set>
#include <vector>

#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include "retdec/common/address.h"
#include "retdec/bin2llvmir/analyses/reaching_definitions.h"
#include "retdec/bin2llvmir/providers/abi/abi.h"
#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/providers/debugformat.h"
#include "retdec/bin2llvmir/providers/fileimage.h"

namespace retdec {
namespace bin2llvmir {

class ConstantsAnalysis : public llvm::ModulePass
{
	public:
		static char ID;
		ConstantsAnalysis();
		virtual bool runOnModule(llvm::Module& m) override;
		bool runOnModuleCustom(
				llvm::Module& m,
				Config* c,
				Abi* a,
				FileImage* i,
				DebugFormat* d);

	private:
		bool run();
		void checkForGlobalInInstruction(
				ReachingDefinitionsAnalysis& RDA,
				llvm::Instruction* inst,
				llvm::Value* val,
				bool storeValue = false);
		void tagFunctionsWithUsedCryptoGlobals();

	private:
		llvm::Module * _module = nullptr;
		Config* _config = nullptr;
		Abi* _abi = nullptr;
		FileImage* _image = nullptr;
		DebugFormat* _dbgf = nullptr;

		std::unordered_set<llvm::Value*> _toRemove;
};

} // namespace bin2llvmir
} // namespace retdec

#endif

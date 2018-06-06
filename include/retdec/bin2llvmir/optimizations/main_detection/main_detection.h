/**
* @file include/retdec/bin2llvmir/optimizations/main_detection/main_detection.h
* @brief Detect main function.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_MAIN_DETECTION_MAIN_DETECTION_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_MAIN_DETECTION_MAIN_DETECTION_H

#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include "retdec/utils/address.h"
#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/providers/fileimage.h"
#include "retdec/bin2llvmir/providers/names.h"

namespace retdec {
namespace bin2llvmir {

class MainDetection : public llvm::ModulePass
{
	public:
		static char ID;
		MainDetection();
		virtual bool runOnModule(llvm::Module& M) override;
		bool runOnModuleCustom(
				llvm::Module& m,
				Config* c,
				FileImage* img = nullptr,
				NameContainer* names = nullptr);

	private:
		bool run();
		bool skipAnalysis();
		void removeStaticallyLinked();
		retdec::utils::Address getFromFunctionNames();
		retdec::utils::Address getFromContext();
		retdec::utils::Address getFromEntryPointOffset(int offset);
		retdec::utils::Address getFromCrtSetCheckCount();
		retdec::utils::Address getFromInterlockedExchange();

		bool applyResult(retdec::utils::Address mainAddr);

	private:
		llvm::Module* _module = nullptr;
		Config* _config = nullptr;
		FileImage* _image = nullptr;
		NameContainer* _names = nullptr;
};

} // namespace bin2llvmir
} // namespace retdec

#endif

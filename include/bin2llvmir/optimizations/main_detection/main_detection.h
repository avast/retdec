/**
* @file include/bin2llvmir/optimizations/main_detection/main_detection.h
* @brief Detect main function.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef BIN2LLVMIR_OPTIMIZATIONS_MAIN_DETECTION_MAIN_DETECTION_H
#define BIN2LLVMIR_OPTIMIZATIONS_MAIN_DETECTION_MAIN_DETECTION_H

#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include "tl-cpputils/address.h"
#include "bin2llvmir/providers/config.h"
#include "bin2llvmir/providers/fileimage.h"

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
				FileImage* img = nullptr);

	private:
		bool run();
		bool skipAnalysis();
		tl_cpputils::Address getFromFunctionNames();
		tl_cpputils::Address getFromContext();
		tl_cpputils::Address getFromEntryPointOffset(int offset);
		tl_cpputils::Address getFromCrtSetCheckCount();
		tl_cpputils::Address getFromInterlockedExchange();

		bool applyResult(tl_cpputils::Address mainAddr);

	private:
		llvm::Module* _module = nullptr;
		Config* _config = nullptr;
		FileImage* _image = nullptr;
};

} // namespace bin2llvmir

#endif

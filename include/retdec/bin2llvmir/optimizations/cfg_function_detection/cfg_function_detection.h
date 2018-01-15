/**
* @file include/retdec/bin2llvmir/optimizations/cfg_function_detection/cfg_function_detection.h
* @brief Detect functions using control flow graph.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_CFG_FUNCTION_DETECTION_CFG_FUNCTION_DETECTION_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_CFG_FUNCTION_DETECTION_CFG_FUNCTION_DETECTION_H

#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include "retdec/bin2llvmir/providers/asm_instruction.h"
#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/providers/fileimage.h"

namespace retdec {
namespace bin2llvmir {

class CfgFunctionDetection : public llvm::ModulePass
{
	public:
		static char ID;
		CfgFunctionDetection();
		virtual bool runOnModule(llvm::Module& M) override;
		bool runOnModuleCustom(llvm::Module& M, Config* c, FileImage* i);

	private:
		bool run();
		bool runOne();
		bool isArmDataInCode(AsmInstruction& ai);
		llvm::Instruction* isPotentialSplitInstruction(llvm::Instruction* i);

	private:
		llvm::Module* _module = nullptr;
		Config* _config = nullptr;
		FileImage* _image = nullptr;
};

} // namespace bin2llvmir
} // namespace retdec

#endif

/**
 * \file include/retdec/retdec/retdec.h
 * \brief RetDec library.
 * \copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_RETDEC_RETDEC_H
#define RETDEC_RETDEC_RETDEC_H

#include <capstone/capstone.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>

#include "retdec/common/basic_block.h"
#include "retdec/common/function.h"

namespace retdec {

struct LlvmModuleContextPair
{
	LlvmModuleContextPair(LlvmModuleContextPair&&) = default;
	~LlvmModuleContextPair()
	{
		// Order matters: module destructor uses context.
		module.reset();
		context.reset();
	}
	std::unique_ptr<llvm::Module> module;
	std::unique_ptr<llvm::LLVMContext> context;
};

/**
 * \param[in]  inputPath Path the the input file to disassemble.
 * \param[out] fs        Set of functions to fill.
 * \return Pointer to LLVM module created by the disassembly,
 *         or \c nullptr if the disassembly failed.
 */
LlvmModuleContextPair disassemble(
		const std::string& inputPath,
		retdec::common::FunctionSet* fs = nullptr);

} // namespace retdec

#endif

/**
 * @file include/retdec/bin2llvmir/optimizations/writer_config/writer_config.h
 * @brief Generate the current config.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_WRITER_CONFIG_WRITER_CONFIG_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_WRITER_CONFIG_WRITER_CONFIG_H

#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

namespace retdec {
namespace bin2llvmir {

class ConfigWriter : public llvm::ModulePass
{
	public:
		static char ID;
		ConfigWriter();
		virtual bool runOnModule(llvm::Module& M) override;
};

} // namespace bin2llvmir
} // namespace retdec

#endif

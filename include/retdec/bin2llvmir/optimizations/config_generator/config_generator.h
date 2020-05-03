/**
 * @file include/retdec/bin2llvmir/optimizations/config_generator/config_generator.h
 * @brief Generate the current config.
 * @copyright (c) 2020 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_CONFIG_GENERATOR_CONFIG_GENERATOR_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_CONFIG_GENERATOR_CONFIG_GENERATOR_H

#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

namespace retdec {
namespace bin2llvmir {

class ConfigGenerator : public llvm::ModulePass
{
	public:
		static char ID;
		ConfigGenerator();
		virtual bool runOnModule(llvm::Module& M) override;
};

} // namespace bin2llvmir
} // namespace retdec

#endif

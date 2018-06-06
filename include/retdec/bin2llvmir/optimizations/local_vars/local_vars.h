/**
* @file include/retdec/bin2llvmir/optimizations/local_vars/local_vars.h
* @brief Register localization.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_LOCAL_VARS_LOCAL_VARS_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_LOCAL_VARS_LOCAL_VARS_H

#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

namespace retdec {
namespace bin2llvmir {

/**
 * TODO: We either should not be doing this at all, or be doing it in mor
 * robust and safe way and for much more cases.
 */
class LocalVars : public llvm::ModulePass
{
	public:
		static char ID;
		LocalVars();
		virtual bool runOnModule(llvm::Module& M) override;
};

} // namespace bin2llvmir
} // namespace retdec

#endif

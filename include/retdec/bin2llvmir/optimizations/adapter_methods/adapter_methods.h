/**
 * @file include/retdec/bin2llvmir/optimizations/adapter_methods/adapter_methods.h
 * @brief Detection of C++ adapter metods created by compiler.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_ADAPTER_METHODS_ADAPTER_METHODS_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_ADAPTER_METHODS_ADAPTER_METHODS_H

#include <map>

#include <llvm/IR/Function.h>
#include <llvm/Pass.h>

#include "retdec/bin2llvmir/providers/config.h"

namespace retdec {
namespace bin2llvmir {

/**
 * This pass finds functions which are adapters to other functions.
 * They typically either directly call some other function or do some simple
 * arithmetics and then make the call.
 *
 * This pass *MUST* run after -instcombine to make instruction matching
 * simple (possible).
 *
 * Right now only one known patter is implemented.
 * When other patterns are found implement them here as separate functions.
 *
 * TODO: Right now, information is gathered but not used.
 * Use it in JSON config, modify functions' names or add functions' comments.
 */
class AdapterMethods: public llvm::FunctionPass
{
	public:
		static char ID;
		AdapterMethods();
		virtual void getAnalysisUsage(llvm::AnalysisUsage& AU) const override;
		virtual bool runOnFunction(llvm::Function& F) override;

	private:
		using AdapterToAdapteeMap = std::map<
				const llvm::Function*,
				const llvm::Function*>;

	private:
		void searchForPattern1(llvm::Function& F);
		// more patterns ...
		void handleAdapter(llvm::Function* adapter, llvm::Function* target);

	private:
		AdapterToAdapteeMap _adapters;
		Config* config = nullptr;
};

} // namespace bin2llvmir
} // namespace retdec

#endif

/**
 * @file include/retdec/bin2llvmir/optimizations/volatilize/volatilize.h
 * @brief Make all loads and stores volatile to protected them.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_VOLATILIZE_VOLATILIZE_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_VOLATILIZE_VOLATILIZE_H

#include <set>

#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include "retdec/bin2llvmir/utils/defs.h"

namespace retdec {
namespace bin2llvmir {

/**
 * This pass may either volatilize (state 1) or unvolatilize (state 2)
 * all loads and stores, depending on the state it is in.
 *
 * State 1 (default state) (volatilize):
 * All loads and stores are volatilized to protect them from bin2llvmirl
 * optimizations. Operations which already have been volatile before
 * this process are noted. State is changed to 2.
 *
 * State 2 (unvolatilize):
 * All loads and stores which are not noted (were not volatile before
 * state 1) are unvolatilized. State is changed to 1.
 *
 * Typical usage in pass chain:
 *     (state 1) -volatilize (state 2 = operations protected)
 *     BIN2LLVMIRL_PASSES (simplify LLVM IR but do not remove memory accesses)
 *     DECOMPILER_PASSES
 *     (state 2) -volatilize (state 1 = operations unprotected)
 */
class Volatilize : public llvm::ModulePass
{
	public:
		static char ID;
		Volatilize();
		virtual bool runOnModule(llvm::Module& M) override;

	private:
		bool volatilize(llvm::Module& M);
		bool unvolatilize(llvm::Module& M);

	private:
		static bool _doVolatilization;
		static UnorderedValSet _alreadyVolatile;
};

} // namespace bin2llvmir
} // namespace retdec

#endif

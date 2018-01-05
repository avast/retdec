/*
* @file include/retdec/llvmir2hll/support/unreachable_funcs_remover.h
* @brief Removes functions that are not reachable from the main function.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_SUPPORT_UNREACHABLE_FUNCS_REMOVER_H
#define RETDEC_LLVMIR2HLL_SUPPORT_UNREACHABLE_FUNCS_REMOVER_H

#include <string>

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
namespace llvmir2hll {

class Module;

/**
* @brief Removes functions that are not reachable from the main function.
*
* For more information, see the description of removeFuncs().
*
* This class implements the "static helper" (or "library") design pattern (it
* has just static functions and no public instances can be created).
*/
class UnreachableFuncsRemover: private retdec::utils::NonCopyable {
public:
	// It needs to be public so it can be called in ShPtr's destructor.
	~UnreachableFuncsRemover();

	static FuncVector removeFuncs(ShPtr<Module> module,
		const std::string &mainFuncName);

private:
	UnreachableFuncsRemover(ShPtr<Module> module,
		const std::string &mainFuncName);

	void performRemoval();

private:
	/// Module in which the functions are removed.
	ShPtr<Module> module;

	/// Name of the main function.
	std::string mainFuncName;

	/// Set of functions that were removed.
	FuncVector removedFuncs;
};

} // namespace llvmir2hll
} // namespace retdec

#endif

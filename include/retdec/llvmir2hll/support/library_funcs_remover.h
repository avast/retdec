/*
* @file include/retdec/llvmir2hll/support/library_funcs_remover.h
* @brief Removes defined functions which are from some standard library whose
*        header file has to be included because of some function declarations.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_SUPPORT_LIBRARY_FUNCS_REMOVER_H
#define RETDEC_LLVMIR2HLL_SUPPORT_LIBRARY_FUNCS_REMOVER_H

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
namespace llvmir2hll {

class Module;

/**
* @brief Removes defined functions which are from some standard library whose
*        header file has to be included because of some function declarations.
*
* For more information, see the description of removeFuncs().
*
* This class implements the "static helper" (or "library") design pattern (it
* has just static functions and no public instances can be created).
*/
class LibraryFuncsRemover: private retdec::utils::NonCopyable {
public:
	static FuncVector removeFuncs(ShPtr<Module> module);
};

} // namespace llvmir2hll
} // namespace retdec

#endif

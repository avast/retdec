/*
* @file include/llvmir2hll/support/headers_for_declared_funcs.h
* @brief Retrieval of header files for all the declared functions in a module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef LLVMIR2HLL_SUPPORT_HEADERS_FOR_DECLARED_FUNCS_H
#define LLVMIR2HLL_SUPPORT_HEADERS_FOR_DECLARED_FUNCS_H

#include "llvmir2hll/support/smart_ptr.h"
#include "llvmir2hll/support/types.h"
#include "tl-cpputils/non_copyable.h"

namespace llvmir2hll {

class Module;

/**
* @brief Retrieval of header files for all the declared functions in a module.
*
* For more information, see the description of getHeaders().
*
* This class implements the "static helper" (or "library") design pattern (it
* has just static functions and no public instances can be created).
*/
class HeadersForDeclaredFuncs: private tl_cpputils::NonCopyable {
public:
	static StringSet getHeaders(ShPtr<Module> module);
	static bool hasAssocHeader(ShPtr<Module> module, ShPtr<Function> func);
};

} // namespace llvmir2hll

#endif

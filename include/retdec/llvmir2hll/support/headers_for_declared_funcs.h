/*
* @file include/retdec/llvmir2hll/support/headers_for_declared_funcs.h
* @brief Retrieval of header files for all the declared functions in a module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_SUPPORT_HEADERS_FOR_DECLARED_FUNCS_H
#define RETDEC_LLVMIR2HLL_SUPPORT_HEADERS_FOR_DECLARED_FUNCS_H

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
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
class HeadersForDeclaredFuncs: private retdec::utils::NonCopyable {
public:
	static StringSet getHeaders(ShPtr<Module> module);
	static bool hasAssocHeader(ShPtr<Module> module, ShPtr<Function> func);
};

} // namespace llvmir2hll
} // namespace retdec

#endif

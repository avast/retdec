/**
* @file src/llvmir2hll/support/headers_for_declared_funcs.cpp
* @brief Implementation of HeadersForDeclaredFuncs.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/semantics/semantics.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/headers_for_declared_funcs.h"
#include "retdec/llvmir2hll/support/maybe.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Returns the header files for all the declared functions in @a module.
*
* @param[in] module Module in which the declarations are considered.
*
* To obtain the header files, this the semantics used by @a module is utilized.
*
* @par Preconditions
*  - @a module is non-null
*/
StringSet HeadersForDeclaredFuncs::getHeaders(ShPtr<Module> module) {
	PRECONDITION_NON_NULL(module);

	StringSet headers;
	for (auto i = module->func_declaration_begin(),
			e = module->func_declaration_end(); i != e; ++i) {
		Maybe<std::string> header(
			module->getSemantics()->getCHeaderFileForFunc((*i)->getName()));
		if (header) {
			headers.insert(header.get());
		}
	}
	return headers;
}

/**
* @brief Returns @c true if the given function has associated a header file, @c
*        false otherwise.
*/
bool HeadersForDeclaredFuncs::hasAssocHeader(ShPtr<Module> module,
		ShPtr<Function> func) {
	return static_cast<bool>(module->getSemantics()->getCHeaderFileForFunc(
		func->getName()));
}

} // namespace llvmir2hll
} // namespace retdec

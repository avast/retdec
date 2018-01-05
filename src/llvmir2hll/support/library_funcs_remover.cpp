/**
* @file src/llvmir2hll/support/library_funcs_remover.cpp
* @brief Implementation of LibraryFuncsRemover.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/semantics/semantics.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/headers_for_declared_funcs.h"
#include "retdec/llvmir2hll/support/library_funcs_remover.h"
#include "retdec/llvmir2hll/support/maybe.h"
#include "retdec/utils/container.h"

using retdec::utils::hasItem;

namespace retdec {
namespace llvmir2hll {

namespace {

/**
* @brief Is the given function from a standard library?
*
* @param[in] func Function to be checked.
* @param[in] module Module from which the function comes.
* @param[in] headers Headers for declared functions in the module.
*/
bool isLibraryFunc(ShPtr<Function> func, ShPtr<Module> module,
		const StringSet &headers) {
	Maybe<std::string> header(
		module->getSemantics()->getCHeaderFileForFunc(func->getName())
	);
	if (!header) {
		// There is no header for the function.
		return false;
	}

	if (!hasItem(headers, header.get())) {
		// The function is not from any of the included headers.
		return false;
	}

	if (module->isExportedFunc(func)) {
		return false;
	}

	return true;
}

/**
* @brief Converts the given function from a standard library into a library
*        function.
*
* @param[in] func Function to be converted.
* @param[in,out] module Module from which the function comes.
*/
void markAsLibraryFunc(ShPtr<Function> func, ShPtr<Module> module) {
	func->convertToDeclaration();
	module->markFuncAsStaticallyLinked(func);
}

} // anonymous namespace

/**
* @brief Removes defined functions in @a module which are from some standard
*        library whose header file has to be included because of some function
*        declaration.
*
* @param[in,out] module Module in which the functions are to be removed.
*
* @return Functions that were turned into declarations.
*
* Function definitions that are removed in this way are turned into
* declarations. In this way, we do not loose their prototypes (they are needed,
* e.g., in CHLLWriter).
*
* @par Preconditions
*  - @a module is non-null
*/
FuncVector LibraryFuncsRemover::removeFuncs(ShPtr<Module> module) {
	PRECONDITION_NON_NULL(module);

	FuncVector removedFuncs;

	// We do the removal in the following two steps.
	//
	// (1) First, we obtain the headers of all declared functions in the module.
	//
	StringSet headers(HeadersForDeclaredFuncs::getHeaders(module));

	// (2) Then, we check which of the defined functions are from some of the
	//     headers obtained in step (1). This is done by checking whether there
	//     is a header file associated to the name of a defined function. If
	//     so, we turn such a definition into a declaration.
	for (auto i = module->func_definition_begin(), e = module->func_definition_end();
			i != e; ++i) {
		const auto &func = *i;
		if (isLibraryFunc(func, module, headers)) {
			markAsLibraryFunc(func, module);
			removedFuncs.push_back(func);
		}
	}

	return removedFuncs;
}

} // namespace llvmir2hll
} // namespace retdec

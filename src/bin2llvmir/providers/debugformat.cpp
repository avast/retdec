/**
 * @file src/bin2llvmir/providers/debugformat.cpp
 * @brief Debug format provider for bin2llvmirl.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/bin2llvmir/providers/debugformat.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

//
//=============================================================================
//  DebugFormat
//=============================================================================
//

//
//=============================================================================
//  DebugFormatProvider
//=============================================================================
//

std::map<Module*, DebugFormat> DebugFormatProvider::_module2debug;

/**
 * Create and add to provider a debug info for the given module @a m, file
 * image @a objf, pdb file path @a pdbFile, possible PE image base @a imageBase
 * and demangler @a demangler.
 * @return Created and added debug ingo or @c nullptr if something went wrong
 *         and it was not successfully created.
 */
DebugFormat* DebugFormatProvider::addDebugFormat(
				llvm::Module* m,
				retdec::loader::Image* objf,
				const std::string& pdbFile,
				const retdec::utils::Address& imageBase,
				retdec::demangler::CDemangler* demangler)
{
	if (objf == nullptr)
	{
		return nullptr;
	}

	auto p = _module2debug.emplace(
			m,
			DebugFormat(
					objf,
					pdbFile,
					nullptr, // symbol table -- not needed.
					demangler,
					imageBase));
	return &p.first->second;
}

/**
 * @return Get debug info associated with the given module @a m or @c nullptr
 *         if there is no associated debug info.
 */
DebugFormat* DebugFormatProvider::getDebugFormat(
		llvm::Module* m)
{
	auto f = _module2debug.find(m);
	return f != _module2debug.end() ? &f->second : nullptr;
}

/**
 * Get debug info @a d associated with the module @a m.
 * @param[in]  m  Module for which to get debug info.
 * @param[out] df Set to debug info associated with @a m module, or @c nullptr
 *               if there is no associated debug info.
 * @return @c True if debug info @a d was set ok and can be used.
 *         @c False otherwise.
 */
bool DebugFormatProvider::getDebugFormat(llvm::Module* m, DebugFormat*& df)
{
	df = getDebugFormat(m);
	return df != nullptr;
}

/**
 * Clear all stored data.
 */
void DebugFormatProvider::clear()
{
	_module2debug.clear();
}

} // namespace bin2llvmir
} // namespace retdec

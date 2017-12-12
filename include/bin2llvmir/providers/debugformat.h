/**
 * @file include/bin2llvmir/providers/debugformat.h
 * @brief Debug format provider for bin2llvmirl.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef BIN2LLVMIR_PROVIDERS_DEBUGFORMAT_H
#define BIN2LLVMIR_PROVIDERS_DEBUGFORMAT_H

#include <llvm/IR/Module.h>

#include "bin2llvmir/providers/fileimage.h"
#include "debugformat/debugformat.h"

namespace bin2llvmir {

class DebugFormat : public debugformat::DebugFormat
{
		using debugformat::DebugFormat::DebugFormat;
};

/**
 * Completely static object -- all members and methods are static -> it can be
 * used by anywhere in bin2llvmirl. It provides mapping of modules to debug info
 * associated with them.
 *
 * @attention Even though this is accessible anywhere in bin2llvmirl, use it only
 * in LLVM passes' prologs to initialize pass-local demangler object. All
 * analyses, utils and other modules *MUST NOT* use it. If they need to work
 * with debug info, they should accept it in parameter.
 */
class DebugFormatProvider
{
	private:
		using SymbolTable = std::map<
				tl_cpputils::Address,
				const fileformat::Symbol*>;

	public:
		static DebugFormat* addDebugFormat(
				llvm::Module* m,
				loader::Image* objf,
				const std::string& pdbFile,
				const tl_cpputils::Address& imageBase,
				demangler::CDemangler* demangler);

		static DebugFormat* getDebugFormat(llvm::Module* m);
		static bool getDebugFormat(llvm::Module* m, DebugFormat*& df);

		static void clear();

	private:
		/// Mapping of modules to debug info associated with them.
		static std::map<llvm::Module*, DebugFormat> _module2debug;
};

} // namespace bin2llvmir

#endif

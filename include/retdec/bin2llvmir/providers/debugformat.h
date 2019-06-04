/**
 * @file include/retdec/bin2llvmir/providers/debugformat.h
 * @brief Debug format provider for bin2llvmirl.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_PROVIDERS_DEBUGFORMAT_H
#define RETDEC_BIN2LLVMIR_PROVIDERS_DEBUGFORMAT_H

#include <llvm/IR/Module.h>

#include "retdec/bin2llvmir/providers/fileimage.h"
#include "retdec/debugformat/debugformat.h"

namespace retdec {
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
				retdec::utils::Address,
				const retdec::fileformat::Symbol*>;

	public:
		static DebugFormat* addDebugFormat(
				llvm::Module* m,
				retdec::loader::Image* objf,
				const std::string& pdbFile,
				const retdec::utils::Address& imageBase,
				retdec::demangler::CDemangler* demangler);

		static DebugFormat* getDebugFormat(llvm::Module* m);
		static bool getDebugFormat(llvm::Module* m, DebugFormat*& df);

		static void clear();

	private:
		/// Mapping of modules to debug info associated with them.
		static std::map<llvm::Module*, DebugFormat> _module2debug;
};

} // namespace bin2llvmir
} // namespace retdec

#endif

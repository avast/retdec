/**
 * @file include/retdec/bin2llvmir/providers/demangler.h
 * @brief Demangler provider for bin2llvmirl.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_PROVIDERS_DEMANGLER_H
#define RETDEC_BIN2LLVMIR_PROVIDERS_DEMANGLER_H

#include <map>

#include <llvm/IR/Module.h>

#include "retdec/demangler/demangler.h"
#include "retdec/config/tool_info.h"

namespace retdec {
namespace bin2llvmir {



class Demangler {
	public:
		using FunctionPair = std::pair<
			llvm::Function*,
			std::shared_ptr<retdec::ctypes::Function>>;

	public:
		explicit Demangler (std::unique_ptr<demangler::Demangler> demangler);

		std::string demangleToString(const std::string &mangled);

//		FunctionPair getPairFunction(const std::string &mangled);

	protected:
		std::unique_ptr<demangler::Demangler> _demangler;
};

/**
 * @brief Class creating demanglers.
 */
class DemanglerFactory
{
public:
	static std::unique_ptr<Demangler> getDemangler(const std::string &compiler);

	static std::unique_ptr<Demangler> getItaniumDemangler();

	static std::unique_ptr<Demangler> getMicrosoftDemangler();

	static std::unique_ptr<Demangler> getBorlandDemangler();
};


/**
 * Completely static object -- all members and methods are static -> it can be
 * used by anywhere in bin2llvmirl. It provides mapping of modules to demanglers
 * associated with them.
 *
 * @attention Even though this is accessible anywhere in bin2llvmirl, use it only
 * in LLVM passes' prologs to initialize pass-local demangler object. All
 * analyses, utils and other modules *MUST NOT* use it. If they need to work
 * with demangler, they should accept it in parameter.
 */
class DemanglerProvider
{
	public:
		static Demangler* addDemangler(
				llvm::Module* m,
				const retdec::config::ToolInfoContainer& t);

		static Demangler* getDemangler(llvm::Module* m);
		static bool getDemangler(
				llvm::Module* m,
				Demangler*& d);

		static void clear();

	private:
		/// Mapping of modules to demanglers associated with them.
		static std::map<llvm::Module*, std::unique_ptr<Demangler>> _module2demangler;
};

} // namespace bin2llvmir
} // namespace retdec

#endif

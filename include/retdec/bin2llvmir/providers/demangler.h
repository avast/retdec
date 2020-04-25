/**
 * @file include/retdec/bin2llvmir/providers/demangler.h
 * @brief Demangler provider for bin2llvmirl.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_PROVIDERS_DEMANGLER_H
#define RETDEC_BIN2LLVMIR_PROVIDERS_DEMANGLER_H

#include <map>

#include <llvm/IR/Module.h>

#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/common/tool_info.h"
#include "retdec/demangler/demangler.h"
#include "retdec/ctypesparser/type_config.h"

namespace retdec {

namespace loader {
class Image;
}
namespace ctypes {
class Type;
}

namespace bin2llvmir {

/*
 * @brief Combined interface for Demangler library and ctypes2llvmir translator.
 */
class Demangler
{
public:
	using FunctionPair = std::pair<
		llvm::Function *,
		std::shared_ptr<retdec::ctypes::Function>>;

public:
	Demangler(
		llvm::Module *llvmModule,
		Config *config,
		const std::shared_ptr<ctypesparser::TypeConfig> &typeConfig,
		std::unique_ptr<retdec::demangler::Demangler> demangler);

	std::string demangleToString(const std::string &mangled);

	FunctionPair getPairFunction(const std::string &mangled);

	demangler::Demangler* getDemangler();

private:
	llvm::Type *getLlvmType(std::shared_ptr<retdec::ctypes::Type> type);

private:
	llvm::Module *_llvmModule = nullptr;
	Config *_config = nullptr;
	std::unique_ptr<retdec::ctypes::Module> _ctypesModule;
	std::shared_ptr<ctypesparser::TypeConfig> _typeConfig;
	std::unique_ptr<demangler::Demangler> _demangler;
};

/**
 * @brief Class for creating demanglers.
 */
class DemanglerFactory
{
public:
	static std::unique_ptr<Demangler> getItaniumDemangler(
		llvm::Module *m,
		Config *config,
		const std::shared_ptr<ctypesparser::TypeConfig> &typeConfig);

	static std::unique_ptr<Demangler> getMicrosoftDemangler(
		llvm::Module *m,
		Config *config,
		const std::shared_ptr<ctypesparser::TypeConfig> &typeConfig);

	static std::unique_ptr<Demangler> getBorlandDemangler(
		llvm::Module *m,
		Config *config,
		const std::shared_ptr<ctypesparser::TypeConfig> &typeConfig);
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
	static Demangler *addDemangler(
		llvm::Module *llvmModule,
		Config *config,
		const std::shared_ptr<ctypesparser::TypeConfig> &typeConfig);

	static Demangler *getDemangler(llvm::Module *m);
	static bool getDemangler(
		llvm::Module *m,
		Demangler *&d);

	static void clear();

private:
	/// Mapping of modules to demanglers associated with them.
	static std::map<llvm::Module *, std::unique_ptr<Demangler>> _module2demangler;
};

} // namespace bin2llvmir
} // namespace retdec

#endif

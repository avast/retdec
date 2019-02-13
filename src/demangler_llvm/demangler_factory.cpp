/**
 * @file src/demangler_llvm/demangler_factory.cpp
 * @brief Demangler factory class.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#include <memory>

#include "llvm/Demangle/demangler_factory.h"

namespace retdec {
namespace demangler {

/**
 * @brief Abstracts instation logic, when we want specific demangler.
 * @param compiler Name of compiler mangling scheme.
 * @return Specific demangler on success or nullptr on failure.
 */
std::unique_ptr<Demangler> DemanglerFactory::getDemangler(const std::string &compiler)
{
	if (compiler == "itanium") {
		return getItaniumDemangler();
	} else if (compiler == "microsoft") {
		return getMicrosoftDemangler();
	} else if (compiler == "borland") {
		return getBorlandDemangler();
	}
	return nullptr;
}

/**
 * @brief Crates new instance of ItaniumDemangler.
 * @return unique_ptr to created demangler instance
 */
std::unique_ptr<ItaniumDemangler> DemanglerFactory::getItaniumDemangler()
{
	return std::make_unique<ItaniumDemangler>();
}

/**
 * @brief Crates new instance of MicrosoftDemangler.
 * @return unique_ptr to created demangler instance
 */
std::unique_ptr<MicrosoftDemangler> DemanglerFactory::getMicrosoftDemangler()
{
	return std::make_unique<MicrosoftDemangler>();
}

/**
 * @brief Crates new instance of BorlandDemangler.
 * @return unique_ptr to created demangler instance
 */
std::unique_ptr<BorlandDemangler> DemanglerFactory::getBorlandDemangler()
{
	return std::make_unique<BorlandDemangler>();
}

}
}


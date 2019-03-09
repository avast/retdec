/**
 * @file include/retdec/demangler/demangler_retdec.h
 * @brief Demangler factory class. Should be included for demangling work.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_LLVM_DEMANGLER_BUILDER_H
#define RETDEC_LLVM_DEMANGLER_BUILDER_H

#include <memory>

#include "retdec/demangler/demangler_base.h"
#include "retdec/demangler/itanium_demangler.h"
#include "retdec/demangler/microsoft_demangler.h"
#include "retdec/demangler/borland_demangler.h"

namespace retdec {
namespace demangler {

/**
 * @brief Class creating demanglers.
 */
class DemanglerFactory
{
	public:
		static std::unique_ptr<Demangler> getDemangler(const std::string &compiler);

		static std::unique_ptr<ItaniumDemangler> getItaniumDemangler();

		static std::unique_ptr<MicrosoftDemangler> getMicrosoftDemangler();

		static std::unique_ptr<BorlandDemangler> getBorlandDemangler();
};

}
}

#endif //RETDEC_LLVM_DEMANGLER_BUILDER_H

/**
 * @file include/retdec/demangler/microsoft_demangler.h
 * @brief Microsoft demangler adapter.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_LLVM_MICROSOFT_DEMANGLER_H
#define RETDEC_LLVM_MICROSOFT_DEMANGLER_H

#include "retdec/demangler/demangler_base.h"

namespace retdec {
namespace demangler {

/**
 * @brief Adapter for llvm microsoft demangler.
 */
class MicrosoftDemangler: public Demangler
{
	public:
		MicrosoftDemangler();

		std::string demangleToString(const std::string &mangled) override;
};

}
}

#endif //RETDEC_LLVM_MICROSOFT_DEMANGLER_H

/**
 * @file include/retdec/demangler/itanium_demangler.h
 * @brief Itanium demangler adapter.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_LLVM_ITANIUM_DEMANGLER_H
#define RETDEC_LLVM_ITANIUM_DEMANGLER_H

#include "retdec/demangler/demangler_base.h"

namespace retdec {
namespace demangler {

/**
 * @brief Adapter for llvm itanium demangler.
 */
class ItaniumDemangler : public Demangler
{
public:
	ItaniumDemangler();

	std::string demangleToString(const std::string &mangled) override;

	std::shared_ptr<ctypes::Function> demangleFunctionToCtypes(
		const std::string &mangled,
		std::unique_ptr<ctypes::Module> &module,
		const ctypesparser::CTypesParser::TypeWidths &typeWidths,
		const ctypesparser::CTypesParser::TypeSignedness &typeSignedness,
		unsigned defaultBitWidth) override;
};

}
}

#endif //RETDEC_LLVM_ITANIUM_DEMANGLER_H

/**
 * @file include/retdec/demangler/borland_demangler.h
 * @brief Borland demangler adapter.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_LLVM_BORLAND_DEMANGLER_H
#define RETDEC_LLVM_BORLAND_DEMANGLER_H

#include "retdec/demangler/demangler_base.h"
#include "retdec/demangler/borland_ast_parser.h"
#include "retdec/ctypes/context.h"

namespace retdec {
namespace demangler {

/**
 * @brief Borland demangler.
 */
class BorlandDemangler : public Demangler
{
public:
	BorlandDemangler();

	std::string demangleToString(const std::string &mangled) override;

	void demangleToModule(const std::string &mangled, retdec::ctypes::Module &module) override;

private:
	borland::Context _demangleContext;
};

}
}

#endif //RETDEC_LLVM_BORLAND_DEMANGLER_H

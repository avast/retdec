/**
 * @file include/retdec/demangler/borland_demangler.h
 * @brief Borland demangler adapter.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_LLVM_BORLAND_DEMANGLER_H
#define RETDEC_LLVM_BORLAND_DEMANGLER_H

#include "retdec/demangler/demangler_base.h"
#include "retdec/demangler/context.h"

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

private:
	borland::Context _context;
};

}
}

#endif //RETDEC_LLVM_BORLAND_DEMANGLER_H

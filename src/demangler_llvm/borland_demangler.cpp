/**
 * @file src/demangler_llvm/borland_demangler.cpp
 * @brief Implementation of borland demangler.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#include "llvm/Demangle/borland_demangler.h"

namespace retdec {
namespace demangler {

BorlandDemangler::BorlandDemangler(): Demangler("borland") {}

std::string BorlandDemangler::demangleToString(const std::string &mangled) {
	return mangled;
}

}
}

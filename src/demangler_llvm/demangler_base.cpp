/**
 * @file src/demangler_llvm/demangler_base.cpp
 * @brief Demangler library implementation.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#include "llvm/Demangle/demangler_base.h"

namespace retdec {
namespace demangler {

/**
 * Abstract constructor.
 * @param compiler Name of compiler mangling scheme.
 */
Demangler::Demangler(const std::string &compiler) :
	_compiler(compiler), _status(success) {}

/**
 * @return Currend demangler status.
 */
Demangler::Status Demangler::status()
{
	return _status;
}

}
}
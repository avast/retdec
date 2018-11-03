/**
 * @file src/demangler_llvm/microsoft_demangler_adapter.cpp
 * @brief Implementation of microsoft demangler adapter.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#include "llvm/Demangle/microsoft_demangler.h"
#include "llvm/Demangle/Demangle.h"

namespace retdec {
namespace demangler {

/**
 * @brief Constructor for adapter.
 */
MicrosoftDemangler::MicrosoftDemangler() : Demangler("microsoft") {}

/**
 * @brief Method for demangling to string. After use demangler status should be checked.
 * @param mangled Name mangled by microsoft mangling scheme.
 * @return Demangled name.
 */
std::string MicrosoftDemangler::demangleToString(const std::string &mangled)
{
	const char *mangled_c = mangled.c_str();
	int llvm_status{};

	const char *demangled_c = llvm::microsoftDemangle(mangled_c, nullptr, nullptr, &llvm_status);

	switch (llvm_status) {
	case llvm::demangle_success:
		_status = success;
		return {demangled_c};
	case llvm::demangle_invalid_mangled_name:
		_status = invalid_mangled_name;
		break;
	case llvm::demangle_memory_alloc_failure:
		_status = memory_alloc_failure;
		break;
	default:
		_status = unknown;
		break;
	}

	return "";
}

}
}

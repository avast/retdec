/**
 * @file src/demangler_llvm/itanium_demangler_adapter.cpp
 * @brief Implementation of itanium demangler adapter.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#include "retdec/demangler/itanium_demangler.h"
#include "llvm/Demangle/Demangle.h"

namespace retdec {
namespace demangler {

/**
 * @brief Constructor for adapter.
 */
ItaniumDemangler::ItaniumDemangler() : Demangler("itanium") {}

/**
 * @brief Method for demangling to string. After use demangler status should be checked.
 * @param mangled Name mangled by itanium mangling scheme.
 * @return Demangled name.
 */
std::string ItaniumDemangler::demangleToString(const std::string &mangled)
{
	const char *mangled_c = mangled.c_str();
	std::string demangled_str = "";
	int llvm_status{};

	char *demangled_c = llvm::itaniumDemangle(mangled_c, nullptr, nullptr, &llvm_status);

	switch (llvm_status) {
	case llvm::demangle_success:
		_status = success;
		demangled_str = demangled_c;
		free(demangled_c);
		break;
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

	return demangled_str;
}

}
}

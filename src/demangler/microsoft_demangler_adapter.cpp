/**
 * @file src/demangler/microsoft_demangler_adapter.cpp
 * @brief Implementation of microsoft demangler adapter.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#include <llvm/Demangle/Demangle.h>
#include <llvm/Demangle/MicrosoftDemangle.h>

#include "retdec/demangler/microsoft_demangler.h"
#include "retdec/demangler/ms_ast_ctypes_parser.h"

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
	std::string demangled_str = "";
	int llvm_status{};

	char *demangled_c = llvm::microsoftDemangle(mangled_c, nullptr, nullptr, &llvm_status);

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

std::shared_ptr<ctypes::Function> MicrosoftDemangler::demangleFunctionToCtypes(
	const std::string &mangled,
	std::unique_ptr<ctypes::Module> &module,
	const ctypesparser::CTypesParser::TypeWidths &typeWidths,
	const ctypesparser::CTypesParser::TypeSignedness &typeSignedness,
	unsigned defaultBitWidth)
{
	llvm::ms_demangle::ArenaAllocator Arena;
	llvm::ms_demangle::Demangler D(Arena);

	StringView Name{mangled.c_str()};
	llvm::ms_demangle::SymbolNode *AST = D.parse(Name);

	if (D.Error) {
		_status = invalid_mangled_name;
		return nullptr;
	}

	std::shared_ptr<ctypes::Function> func;
	MsToCtypesParser parser;
	func = parser.parseAsFunction(
			mangled,
			AST,
			module,
			typeWidths,
			typeSignedness,
			defaultBitWidth);
	if (func) {
		_status = success;
	}
	return func;
}

} // demangler
} // retdec

/**
 * @file src/demangler/itanium_demangler_adapter.cpp
 * @brief Implementation of itanium demangler adapter.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#include <llvm/Demangle/ItaniumDemangle.h>
#include <llvm/Demangle/Demangle.h>
#include <llvm/Demangle/Allocator.h>
#include <llvm/Demangle/Utility.h>

#include "retdec/demangler/itanium_ast_ctypes_parser.h"
#include "retdec/demangler/itanium_demangler.h"

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

std::shared_ptr<ctypes::Function> ItaniumDemangler::demangleFunctionToCtypes(
	const std::string &mangled,
	std::unique_ptr<ctypes::Module> &module,
	const ctypesparser::CTypesParser::TypeWidths &typeWidths,
	const ctypesparser::CTypesParser::TypeSignedness &typeSignedness,
	unsigned defaultBitWidth)
{
	using DefaultAllocator = llvm::itanium_demangle::DefaultAllocator;
	using Demangler = llvm::itanium_demangle::ManglingParser<DefaultAllocator>;

	DefaultAllocator allocator;
	Demangler Parser(mangled.c_str(), mangled.c_str() + mangled.size(), allocator);

	llvm::itanium_demangle::Node *AST = Parser.parse();
	if (AST == nullptr) {
		_status = invalid_mangled_name;
		return nullptr;
	}

	ItaniumAstCtypesParser ctypesParser;
	auto func = ctypesParser.parseAsFunction(
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

}
}

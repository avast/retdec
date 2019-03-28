/**
 * @file src/demangler_llvm/itanium_demangler_adapter.cpp
 * @brief Implementation of itanium demangler adapter.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#include "llvm/Demangle/ItaniumDemangle.h"
#include "llvm/Demangle/Demangle.h"
#include "llvm/Demangle/Allocator.h"
#include "llvm/Demangle/Utility.h"

#include "retdec/demangler/itanium_demangler.h"
#include "retdec/ctypesparser/itanium_ast_ctypes_parser.h"

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

void ItaniumDemangler::demangleToModule(
	const std::string &mangled, std::shared_ptr<retdec::ctypes::Module> &module)
{
	using DefaultAllocator = llvm::itanium_demangle::DefaultAllocator;
	using Demangler = llvm::itanium_demangle::ManglingParser<DefaultAllocator>;

	DefaultAllocator allocator;
	Demangler Parser(mangled.c_str(), mangled.c_str() + mangled.size(), allocator);

	llvm::itanium_demangle::Node *AST = Parser.parse();

	// TODO better propagation
	if (AST == nullptr) {
		_status = invalid_mangled_name;
	}

	_status = success;

	static const ctypesparser::CTypesParser::TypeWidths typeWidths = {
		{"void", 0},
		{"bool", 1},
		{"char", 8},
		{"signed char", 8},
		{"unsigned char", 8},
		{"wchar_t", 32},
		{"short", 16},
		{"unsigned short", 16},
		{"int", 32},
		{"unsigned int", 32},
		{"long", 64},
		{"unsigned long", 64},
		{"long long", 64},
		{"unsigned long long", 64},
		{"int64_t", 64},
		{"uint64_t", 64},
		{"float", 32},
		{"double", 64},
		{"long double", 96},
		{"pointer", 32}
	};

	static const ctypesparser::CTypesParser::TypeSignedness typeSignedness = {
		{"wchar_t", ctypes::IntegralType::Signess::Unsigned},
		{"char16_t", ctypes::IntegralType::Signess::Unsigned},
		{"char32_t", ctypes::IntegralType::Signess::Unsigned},
		{"char", ctypes::IntegralType::Signess::Unsigned},
	};

	ctypes::CallConvention defaultCallConv;

	if (_status == success) {
		ctypesparser::ItaniumAstCtypesParser ctypesParser;
		ctypesParser.parseAsFunction(AST, module, typeWidths, typeSignedness, defaultCallConv);
	}
}

std::shared_ptr<ctypes::Function> ItaniumDemangler::demangleFunctionToCtypes(
	const std::string &mangled, std::shared_ptr<retdec::ctypes::Module> &module)
{
	using DefaultAllocator = llvm::itanium_demangle::DefaultAllocator;
	using Demangler = llvm::itanium_demangle::ManglingParser<DefaultAllocator>;

	DefaultAllocator allocator;
	Demangler Parser(mangled.c_str(), mangled.c_str() + mangled.size(), allocator);

	llvm::itanium_demangle::Node *AST = Parser.parse();

	// TODO better propagation
	if (AST == nullptr) {
		_status = invalid_mangled_name;
	}

	_status = success;

	static const ctypesparser::CTypesParser::TypeWidths typeWidths = {
		{"void", 0},
		{"bool", 1},
		{"char", 8},
		{"signed char", 8},
		{"unsigned char", 8},
		{"wchar_t", 32},
		{"short", 16},
		{"unsigned short", 16},
		{"int", 32},
		{"unsigned int", 32},
		{"long", 64},
		{"unsigned long", 64},
		{"long long", 64},
		{"unsigned long long", 64},
		{"int64_t", 64},
		{"uint64_t", 64},
		{"float", 32},
		{"double", 64},
		{"long double", 96},
		{"pointer", 32}
	};

	static const ctypesparser::CTypesParser::TypeSignedness typeSignedness = {
		{"wchar_t", ctypes::IntegralType::Signess::Unsigned},
		{"char16_t", ctypes::IntegralType::Signess::Unsigned},
		{"char32_t", ctypes::IntegralType::Signess::Unsigned},
		{"char", ctypes::IntegralType::Signess::Unsigned},
	};

	std::shared_ptr<ctypes::Function> func;
	if (_status == success) {
		ctypes::CallConvention defaultCallConv;
		ctypesparser::ItaniumAstCtypesParser ctypesParser;
		func = ctypesParser.parseAsFunction(AST, module, typeWidths, typeSignedness, defaultCallConv);
	}

	_status = func? success: invalid_mangled_name;	// TODO different status if fail
	return func;
}

}
}

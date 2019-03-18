/**
 * @file src/demangler_llvm/microsoft_demangler_adapter.cpp
 * @brief Implementation of microsoft demangler adapter.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */


#include "llvm/Demangle/Demangle.h"
#include "llvm/Demangle/MicrosoftDemangle.h"

#include "retdec/demangler/microsoft_demangler.h"
#include "retdec/ctypesparser/ms_ast_ctypes_parser.h"

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

void MicrosoftDemangler::demangleToModule(
	const std::string &mangled,
	std::unique_ptr<retdec::ctypes::Module> &module)
{
	llvm::ms_demangle::ArenaAllocator Arena;
	llvm::ms_demangle::Demangler D(Arena);
	OutputStream S;

	StringView Name{mangled.c_str()};
	llvm::ms_demangle::SymbolNode *AST = D.parse(Name);

//	if (Flags & MSDF_DumpBackrefs)
//		D.dumpBackReferences();

	if (D.Error) {
		_status = invalid_mangled_name;
	}

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

	ctypesparser::MsToCtypesParser parser;
	parser.parseInto(AST, module, typeWidths, typeSignedness);

	_status = success; // TODO
}

}
}

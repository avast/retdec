/**
 * @file src/demangler_llvm/borland_demangler.cpp
 * @brief Implementation of borland demangler.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#include "retdec/demangler/borland_demangler.h"
#include "retdec/demangler/borland_ast_parser.h"
#include "retdec/ctypesparser/borland_ast_ctypes_parser.h"

namespace {
/**
 * Checks ast parser status and converts it to demangler status.
 * @return Demangler status.
 */
retdec::demangler::Demangler::Status astStatusToDemStatus(const retdec::demangler::borland::BorlandASTParser::Status &parserStatus)
{
	switch (parserStatus) {
	case retdec::demangler::borland::BorlandASTParser::Status::success:
		return retdec::demangler::Demangler::Status::success;
	case retdec::demangler::borland::BorlandASTParser::Status::invalid_mangled_name:
		return retdec::demangler::Demangler::Status::invalid_mangled_name;
	default:
		return retdec::demangler::Demangler::Status::unknown;
	}
}

/**
 * Checks demangler status and returns demangled string.
 */
std::string astToString(
	const retdec::demangler::Demangler::Status &status,
	const std::shared_ptr<retdec::demangler::borland::Node> &ast)
{
	if (status == retdec::demangler::Demangler::Status::success && ast) {
		return ast->str();
	} else {
		return std::string{};
	}
}

}    // anonymous namespace

namespace retdec {
namespace demangler {

/**
 * @brief Constructor for borland demangler.
 */
BorlandDemangler::BorlandDemangler() : Demangler("borland"), _demangleContext() {}

/**
 * @brief Demangles name mangled by borland mangling scheme into string.
 * @param mangled Name mangled by borland mangling scheme.
 * @return Demangled name.
 */
std::string BorlandDemangler::demangleToString(const std::string &mangled)
{
	borland::BorlandASTParser parser{_demangleContext};
	parser.parse(mangled);
	_status = astStatusToDemStatus(parser.status());
	return astToString(_status, parser.ast());
}

std::shared_ptr<ctypes::Function> BorlandDemangler::demangleFunctionToCtypes(
	const std::string &mangled, std::shared_ptr<retdec::ctypes::Module> &module)
{
	borland::BorlandASTParser astParser{_demangleContext};
	astParser.parse(mangled);
	_status = astStatusToDemStatus(astParser.status());
	if (_status != success) {
		return nullptr;
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
	}; // TODO getvalordefault

	static const ctypesparser::CTypesParser::TypeSignedness typeSignedness = {
		{"wchar_t", ctypes::IntegralType::Signess::Unsigned},
		{"char16_t", ctypes::IntegralType::Signess::Unsigned},
		{"char32_t", ctypes::IntegralType::Signess::Unsigned},
		{"char", ctypes::IntegralType::Signess::Unsigned},
	};

	ctypesparser::BorlandToCtypesParser ctypesParser{};
	auto func = ctypesParser.parseAsFunction(mangled, astParser.ast(), module, typeWidths, typeSignedness);
	_status = func ? success: invalid_mangled_name;
	return func;
}

} // demangler
} // retdec

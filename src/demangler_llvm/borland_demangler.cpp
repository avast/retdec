/**
 * @file src/demangler_llvm/borland_demangler.cpp
 * @brief Implementation of borland demangler.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#include "llvm/Demangle/borland_demangler.h"
#include "llvm/Demangle/borland_ast_parser.h"
#include "retdec/ctypesparser/borland_ast_ctypes_parser.h"

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
	return astToString(parser.ast());
}

void BorlandDemangler::demangleToModule(const std::string &mangled, retdec::ctypes::Module &module)
{
	borland::BorlandASTParser astParser{_demangleContext};
	astParser.parse(mangled);
	_status = astStatusToDemStatus(astParser.status());
	if (_status != success) {
		return;
	}

	ctypesparser::borland_ast::BorlandToCtypesParser ctypesParser{};
	ctypesParser.parseInto(astParser.ast(), module);
	_status = success;	// TODO
}

/**
 * Checks ast parser status and converts it to demangler status.
 * @return Demangler status.
 */
Demangler::Status BorlandDemangler::astStatusToDemStatus(const retdec::demangler::borland::BorlandASTParser::Status &parserStatus)
{
	switch (parserStatus) {
	case borland::BorlandASTParser::Status::success:
		return success;
	case borland::BorlandASTParser::Status::invalid_mangled_name:
		return invalid_mangled_name;
	default:
		return unknown;
	}
}

/**
 * Checks demangler status and returns demangled string.
 */
std::string BorlandDemangler::astToString(const std::shared_ptr<retdec::demangler::borland::Node> &ast) const
{
	if (_status == success && ast) {
		return ast->str();
	} else {
		return std::string{};
	}
}

} // demangler
} // retdec

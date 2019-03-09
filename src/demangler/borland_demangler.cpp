/**
 * @file src/demangler_llvm/borland_demangler.cpp
 * @brief Implementation of borland demangler.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#include "retdec/demangler/borland_demangler.h"
#include "retdec/demangler/borland_ast_parser.h"

namespace retdec {
namespace demangler {

/**
 * @brief Constructor for borland demangler.
 */
BorlandDemangler::BorlandDemangler() : Demangler("borland"), _context() {}

/**
 * @brief Demangles name mangled by borland mangling scheme into string.
 * @param mangled Name mangled by borland mangling scheme.
 * @return Demangled name.
 */
std::string BorlandDemangler::demangleToString(const std::string &mangled)
{
	borland::BorlandASTParser parser{_context};
	parser.parse(mangled);
	_status = astStatusToDemStatus(parser.status());
	return astToString(parser.ast());
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

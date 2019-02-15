/**
 * @file src/demangler_llvm/borland_demangler.cpp
 * @brief Implementation of borland demangler.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#include "llvm/Demangle/borland_demangler.h"
#include "llvm/Demangle/borland_ast_parser.h"

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
	_status = Status::unknown;

	borland::BorlandASTParser parser{_context, mangled};

	/* update demanlger status based on parser status */
	auto parserStatus = parser.status();
	switch (parserStatus) {
	case borland::BorlandASTParser::Status::success:
		_status = success;
		break;
	case borland::BorlandASTParser::Status::invalid_mangled_name:
		_status = invalid_mangled_name;
		break;
	default:
		_status = unknown;
	}

	auto ast = parser.ast();
	if (_status == success && ast) {
		return ast->str();
	} else {
		return std::string{};
	}
}

} // demangler
} // retdec

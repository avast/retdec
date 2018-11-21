/**
 * @file include/llvm/Demangle/borland_ast_parser.h
 * @brief Parser of mangled names into tree for borland demangler.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BORLAND_AST_PARSER_H
#define RETDEC_BORLAND_AST_PARSER_H

#include "llvm/Demangle/borland_ast.h"

namespace retdec {
namespace demangler {
namespace borland {

/**
 * @brief Parser from name mangled by borland mangling scheme into AST.
 */
class BorlandASTParser
{
	public:
		enum Status: uint8_t
		{
			success = 0,
			init,
			memory_alloc_failure,
			invalid_mangled_name,
			unknown_error,
		};

	public:
		explicit BorlandASTParser(const std::string &mangled);

		std::shared_ptr<Node> ast();

		Status status();

	private:
		void parse();
		std::unique_ptr<Node> parseFullName();
		static StringView getNestedName(StringView &source);
		std::unique_ptr<CallConv> parseCallConv();

	private:
		Status _status;
		StringView _mangled;
		std::shared_ptr<Node> _ast;
};

}	// borland
}	// demangler
}	// retdec

#endif //RETDEC_BORLAND_AST_PARSER_H

/**
 * @file include/llvm/Demangle/borland_ast_parser.h
 * @brief Parser of mangled names into tree for borland demangler.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BORLAND_AST_PARSER_H
#define RETDEC_BORLAND_AST_PARSER_H

#include "llvm/Demangle/borland_ast.h"
#include "llvm/Demangle/context.h"

namespace retdec {
namespace demangler {
namespace borland {

/**
 * @brief Parser from name mangled by borland mangling scheme into AST.
 */
class BorlandASTParser
{
public:
	enum Status : uint8_t
	{
		success = 0,
		in_progress,
		memory_alloc_failure,
		invalid_mangled_name,
		unknown_error,
	};

public:
	explicit BorlandASTParser(Context &context, const std::string &mangled);

	std::shared_ptr<Node> ast();

	Status status();

private:
	void parse();
	void parseFunction();
	std::pair<bool, bool> parseQualifiers();
	std::shared_ptr<Node> parseAbsoluteName();
	FunctionNode::CallConv parseCallConv();
	std::shared_ptr<NodeArray> parseFuncParams();
	std::shared_ptr<Node> parseType();
	std::shared_ptr<Node> parseBuildInType();
//	unsigned parseNumber();
//	std::unique_ptr<Node> parseNamedType();
//		std::unique_ptr<Node> parseRetType();
//		std::unique_ptr<Node> parseFuncInfo();
	static StringView getNestedName(StringView &source);

private:
	Status _status;
	StringView _mangled;
	std::shared_ptr<Node> _ast;
	Context _context;
};

}    // borland
}    // demangler
}    // retdec

#endif //RETDEC_BORLAND_AST_PARSER_H

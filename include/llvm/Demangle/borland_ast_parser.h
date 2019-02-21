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
		invalid_mangled_name,
		unknown_error,
	};

public:
	explicit BorlandASTParser(Context &context, const std::string &mangled);

	std::shared_ptr<Node> ast();

	Status status();

private:
	unsigned peekNumber() const;
	bool peekChar(char c) const;
	bool statusOk() const;
	bool checkResult(std::shared_ptr<Node> node);
	bool mustConsumeChar(char c);

	void parse();
	void parseFunction();
	Qualifiers parseQualifiers();
	FunctionNode::CallConv parseCallConv();
	std::shared_ptr<NodeArray> parseFuncParams();
	std::shared_ptr<Node> parseType();
	std::shared_ptr<Node> parseBuildInType(const Qualifiers &quals);
	unsigned parseNumber();
	std::shared_ptr<Node> parseNamedType(unsigned nameLen);
	std::shared_ptr<Node> parseFuncName();
	std::shared_ptr<Node> parseName(const char *end);
	std::shared_ptr<Node> parseTemplate(std::shared_ptr<Node> templateNamespace);
	std::shared_ptr<Node> parseTemplate(std::shared_ptr<Node> templateNamespace, const char *end);
	std::shared_ptr<Node> parseArray();

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

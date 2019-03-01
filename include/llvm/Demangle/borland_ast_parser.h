/**
 * @file include/llvm/Demangle/borland_ast_parser.h
 * @brief Parser of mangled names into tree for borland demangler.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BORLAND_AST_PARSER_H
#define RETDEC_BORLAND_AST_PARSER_H

#include "llvm/Demangle/borland_ast.h"
#include "llvm/Demangle/context.h"

#include "llvm/Demangle/StringView.h"

namespace retdec {
namespace demangler {
namespace borland {

class FunctionTypeNode;

using StringView = llvm::itanium_demangle::StringView;

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
	char peek() const;
	bool peekChar(char c) const;
	bool peek(const StringView &s) const;
	unsigned peekNumber() const;
	bool statusOk() const;
	bool checkResult(std::shared_ptr<Node> node);
	bool consumeIfPossible(char c);
	bool consumeIfPossible(const StringView &s);
	bool consume(char c);
	bool consume(const StringView &s);

	void parse();
	void parseFunction();
	std::shared_ptr<FunctionTypeNode> parseFuncType(Qualifiers &quals);
	Qualifiers parseQualifiers();
	CallConv parseCallConv();
	std::shared_ptr<NodeArray> parseFuncParams();
	bool parseBackref(std::shared_ptr<NodeArray> &paramArray);
	std::shared_ptr<Node> parseType();
	std::shared_ptr<Node> parseBuildInType(const Qualifiers &quals);
	unsigned parseNumber();
	std::shared_ptr<Node> parseNamedType(unsigned nameLen, const Qualifiers &quals);
	std::shared_ptr<Node> parseFuncName();
	std::shared_ptr<Node> parseLlvmName();
	std::shared_ptr<Node> parseOperator();
	std::shared_ptr<Node> parseName(const char *end);
	std::shared_ptr<Node> parseTemplateName(std::shared_ptr<Node> templateNamespace);
	std::shared_ptr<Node> parseTemplateParams();
	std::shared_ptr<Node> parseTemplate(std::shared_ptr<Node> templateNamespace);
	std::shared_ptr<Node> parsePointer(const Qualifiers &quals);
	std::shared_ptr<Node> parseReference();
	std::shared_ptr<Node> parseRReference();
	std::shared_ptr<Node> parseArray(const Qualifiers &quals);

	static std::string getString(const StringView &s);
private:
	Status _status;
	StringView _mangled;
	std::shared_ptr<Node> _ast;
	Context &_context;
};

}    // borland
}    // demangler
}    // retdec

#endif //RETDEC_BORLAND_AST_PARSER_H

/**
 * @file include/retdec/demangler/borland_ast_parser.h
 * @brief Parser of mangled names into tree for borland demangler.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BORLAND_AST_PARSER_H
#define RETDEC_BORLAND_AST_PARSER_H

#include <llvm/Demangle/StringView.h>

#include "retdec/demangler/context.h"
#include "retdec/demangler/borland_ast/node.h"

namespace retdec {
namespace demangler {
namespace borland {

using StringView = llvm::itanium_demangle::StringView;

class FunctionTypeNode;
class NodeArray;
enum class CallConv;

/**
 * @brief Parses name mangled by borland mangling scheme into AST.
 */
class BorlandASTParser
{
public:
	enum Status : uint8_t
	{
		success = 0,
		init,
		in_progress,
		invalid_mangled_name,
		unknown_error,
	};

public:
	explicit BorlandASTParser(Context &context);

	void parse(const std::string &mangled);

	std::shared_ptr<Node> ast();

	Status status();

private:
	char peek() const;
	bool peek(char c) const;
	bool peek(const StringView &s) const;
	unsigned peekNumber() const;
	bool statusOk() const;
	bool checkResult(std::shared_ptr<Node> node);
	bool consumeIfPossible(char c);
	bool consumeIfPossible(const StringView &s);
	bool consume(char c);
	bool consume(const StringView &s);

	std::shared_ptr<Node> parseFunction();
	std::shared_ptr<FunctionTypeNode> parseFuncType(Qualifiers &quals);
	Qualifiers parseQualifiers();
	CallConv parseCallConv();
	std::shared_ptr<NodeArray> parseFuncParams();
	bool parseBackref(std::shared_ptr<NodeArray> &paramArray);
	std::shared_ptr<TypeNode> parseType();
	std::shared_ptr<TypeNode> parseBuildInType(const Qualifiers &quals);
	unsigned parseNumber();
	std::shared_ptr<TypeNode> parseNamedType(unsigned nameLen, const Qualifiers &quals);
	std::shared_ptr<Node> parseFuncName();
	std::shared_ptr<Node> parseFuncNameClasic();
	std::shared_ptr<Node> parseFuncNameLlvm();
	bool couldBeOperator();
	std::shared_ptr<Node> parseOperator();
	std::shared_ptr<Node> parseAsNameUntil(const char *end);
	std::shared_ptr<Node> parseTemplate(std::shared_ptr<Node> templateNamespace);
	std::shared_ptr<Node> parseTemplateName(std::shared_ptr<Node> templateNamespace);
	std::shared_ptr<Node> parseTemplateParams();
	std::shared_ptr<TypeNode> parsePointer(const Qualifiers &quals);
	std::shared_ptr<TypeNode> parseReference();
	std::shared_ptr<TypeNode> parseRReference();
	std::shared_ptr<TypeNode> parseArray(const Qualifiers &quals);
	std::shared_ptr<Node> parseIntExpresion(StringView &s);
	unsigned parseNumber(StringView &s);
	bool parseTemplateBackref(
		StringView &mangled,
		std::shared_ptr<NodeArray> &params);
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

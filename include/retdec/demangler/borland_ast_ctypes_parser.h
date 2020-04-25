/**
* @file include/retdec/demangler/ast_ctypes_parser.h
* @brief Parser for AST created in Borland demangler to ctypes parsers.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BORLAND_AST_CTYPES_PARSER_H
#define RETDEC_BORLAND_AST_CTYPES_PARSER_H

#include "retdec/demangler/ast_ctypes_parser.h"
#include "retdec/demangler/borland_ast/borland_ast.h"

namespace retdec {
namespace demangler {

/*
 * @brief Parser for AST created in Borland demangler to ctypes parsers.
 */
class BorlandToCtypesParser : public AstToCtypesParser
{
public:
	BorlandToCtypesParser() = default;

	std::shared_ptr<ctypes::Function> parseAsFunction(
		const std::string &name,
		std::shared_ptr<demangler::borland::Node> ast,
		std::unique_ptr<ctypes::Module> &module,
		const TypeWidths &typeWidths = {},
		const TypeSignedness &typeSignedness = {},
		unsigned defaultBitWidth = 0);

private:
	std::shared_ptr<retdec::ctypes::Function> parseFunction(
		const std::string &mangledName,	std::shared_ptr<demangler::borland::FunctionNode> function);

	std::shared_ptr<ctypes::Type> parseType(
		std::shared_ptr<demangler::borland::TypeNode> typeNode);

	std::shared_ptr<ctypes::IntegralType> parseIntegralType(
		std::shared_ptr<demangler::borland::IntegralTypeNode> integralNode);

	std::shared_ptr<ctypes::FloatingPointType> parseFloatingPointType(
		std::shared_ptr<demangler::borland::FloatTypeNode> floatNode);

	std::shared_ptr<ctypes::IntegralType> parseCharType(
		std::shared_ptr<demangler::borland::CharTypeNode> charNode);

	std::shared_ptr<ctypes::Type> parseBuiltInType(
		std::shared_ptr<demangler::borland::BuiltInTypeNode> typeNode);

	std::shared_ptr<ctypes::PointerType> parsePointerType(
		std::shared_ptr<demangler::borland::PointerTypeNode> pointerNode);

	std::shared_ptr<ctypes::Type> parseReferenceType(
		std::shared_ptr<demangler::borland::ReferenceTypeNode> referenceNode);

	std::shared_ptr<ctypes::Type> parseRReferenceType(
		std::shared_ptr<demangler::borland::RReferenceTypeNode> referenceNode);

	std::shared_ptr<ctypes::NamedType> parseNamedType(
		std::shared_ptr<demangler::borland::NamedTypeNode> namedTypeNode);

	ctypes::Function::Parameters parseFuncParameters(
		std::shared_ptr<demangler::borland::NodeArray> paramsNode);

	ctypes::CallConvention parseCallConvention(
		demangler::borland::CallConv callConv);

	std::shared_ptr<ctypes::FunctionType> parsefuncType(
		std::shared_ptr<demangler::borland::FunctionTypeNode> funcTypeNode);

	ctypes::FunctionType::Parameters parseFuncTypeParameters(
		std::shared_ptr<demangler::borland::NodeArray> paramsNode);

	std::shared_ptr<ctypes::ArrayType> parseArrayType(
		std::shared_ptr<demangler::borland::ArrayNode> ArrayTypeNode);
};

} // demangler
} // retdec

#endif //RETDEC_BORLAND_AST_CTYPES_PARSER_H

/**
* @file src/demangler/borland_ast_ctypes_parser.cpp
* @brief Parser from AST created by Borland demangler to C-types.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#include <cassert>

#include "retdec/ctypes/ctypes.h"
#include "retdec/demangler/borland_ast_ctypes_parser.h"

using Kind = retdec::demangler::borland::Node::Kind;

namespace retdec {
namespace demangler {

/*
 * @brief Entry point for parsing AST representation of functions into ctypes functions.
 * Sets internal variables and checks if root AST node is function.
 *
 */
std::shared_ptr<ctypes::Function> BorlandToCtypesParser::parseAsFunction(
	const std::string &name,
	std::shared_ptr<retdec::demangler::borland::Node> ast,
	std::unique_ptr<ctypes::Module> &module,
	const TypeWidths &typeWidths,
	const TypeSignedness &typeSignedness,
	unsigned defaultBitWidth)
{
	assert(ast && "Ast cannot be null");

	this->context = module->getContext();
	this->typeWidths = typeWidths;
	this->typeSignedness = typeSignedness;
	this->defaultBitWidth = defaultBitWidth;

	std::shared_ptr<ctypes::Function> func = nullptr;

	// do nothing if AST is not function
	if (ast->kind() == Kind::KFunction) {
		func = parseFunction(name, std::static_pointer_cast<demangler::borland::FunctionNode>(ast));
		if (func) {
			module->addFunction(func);
		}
	}

	return func;
}

/*
 * @brief Parses AST into ctypes funtion representation.
 * AST should be valid represent of function.
 */
std::shared_ptr<retdec::ctypes::Function> BorlandToCtypesParser::parseFunction(
	const std::string &mangledName,
	std::shared_ptr<demangler::borland::FunctionNode> function)
{
	assert(function && function->name() && "Violated precondition");

	auto funcType = function->funcType();

	std::shared_ptr<ctypes::Type> returnType = parseType(funcType->retType());
	ctypes::Function::Parameters parameters = parseFuncParameters(funcType->params());
	ctypes::CallConvention callConvention = parseCallConvention(funcType->callConv());
	ctypes::Function::VarArgness varArgness = toVarArgness(funcType->isVarArg());

	auto func = ctypes::Function::create(context, mangledName, returnType, parameters, callConvention, varArgness);
	if (func) {
		auto declaration = function->str();
		func->setDeclaration(ctypes::FunctionDeclaration(declaration));
	}

	return func;
}

/*
 * @brief Parses nodes representing type.
 */
std::shared_ptr<ctypes::Type> BorlandToCtypesParser::parseType(
	std::shared_ptr<retdec::demangler::borland::TypeNode> typeNode)
{
	if (typeNode) {
		switch (typeNode->kind()) {
		case Kind::KIntegralType: {
			auto intType = parseIntegralType(std::static_pointer_cast<demangler::borland::IntegralTypeNode>(typeNode));
			return std::static_pointer_cast<ctypes::Type>(intType);
		}
		case Kind::KFloatType: {
			auto floatType =
				parseFloatingPointType(std::static_pointer_cast<demangler::borland::FloatTypeNode>(typeNode));
			return std::static_pointer_cast<ctypes::Type>(floatType);
		}
		case Kind::KCharType: {
			auto charType = parseCharType(std::static_pointer_cast<demangler::borland::CharTypeNode>(typeNode));
			return std::static_pointer_cast<ctypes::Type>(charType);
		}
		case Kind::KBuiltInType: {
			return parseBuiltInType(std::static_pointer_cast<demangler::borland::BuiltInTypeNode>(typeNode));
		}
		case Kind::KPointerType: {
			auto
				pointerType = parsePointerType(std::static_pointer_cast<demangler::borland::PointerTypeNode>(typeNode));
			return std::static_pointer_cast<ctypes::Type>(pointerType);
		}
		case Kind::KReferenceType: {
			auto referenceType =
				parseReferenceType(std::static_pointer_cast<demangler::borland::ReferenceTypeNode>(typeNode));
			return std::static_pointer_cast<ctypes::Type>(referenceType);
		}
		case Kind::KRReferenceType: {
			auto referenceType =
				parseRReferenceType(std::static_pointer_cast<demangler::borland::RReferenceTypeNode>(typeNode));
			return std::static_pointer_cast<ctypes::Type>(referenceType);
		}
		case Kind::KNamedType: {
			auto namedType = parseNamedType(std::static_pointer_cast<demangler::borland::NamedTypeNode>(typeNode));
			return std::static_pointer_cast<ctypes::Type>(namedType);
		}
		case Kind::KFunctionType: {
			auto funcType = parsefuncType(std::static_pointer_cast<demangler::borland::FunctionTypeNode>(typeNode));
			return std::static_pointer_cast<ctypes::Type>(funcType);
		}
		case Kind::KArrayNode: {
			auto arrayType = parseArrayType(std::static_pointer_cast<demangler::borland::ArrayNode>(typeNode));
			return std::static_pointer_cast<ctypes::Type>(arrayType);
		}
		default:
			break;
		}
	}

	return std::static_pointer_cast<ctypes::Type>(ctypes::UnknownType::create());    // no suitable conversion could be done
}

std::shared_ptr<ctypes::IntegralType> BorlandToCtypesParser::parseIntegralType(
	std::shared_ptr<retdec::demangler::borland::IntegralTypeNode> integralNode)
{
	assert(integralNode && "Node cannot be null");

	std::string name = integralNode->typeName();    // name without qualifiers
	unsigned bitWidth = getBitWidth(name);
	ctypes::IntegralType::Signess signess = toSigness(integralNode->isUnsigned());

	return ctypes::IntegralType::create(context, name, bitWidth, signess);
}

std::shared_ptr<ctypes::FloatingPointType> BorlandToCtypesParser::parseFloatingPointType(
	std::shared_ptr<retdec::demangler::borland::FloatTypeNode> floatNode)
{
	assert(floatNode && "Node cannot be null");

	std::string name = floatNode->typeName();    // name without qualifiers
	unsigned bitWidth = getBitWidth(name);

	return ctypes::FloatingPointType::create(context, name, bitWidth);
}

std::shared_ptr<ctypes::IntegralType> BorlandToCtypesParser::parseCharType(
	std::shared_ptr<retdec::demangler::borland::CharTypeNode> charNode)
{
	assert(charNode && "Node cannot be null");

	std::string name = charNode->typeName();    // name without qualifiers
	unsigned bitWidth = getBitWidth(name);
	ctypes::IntegralType::Signess signess = toSigness(name);

	return ctypes::IntegralType::create(context, name, bitWidth, signess);
}

/*
 * @brief Parses nodes of built-in type.
 * Only types represented by these nodes should be void, bool, wchar_t, char16_t and char32_t.
 */
std::shared_ptr<ctypes::Type> BorlandToCtypesParser::parseBuiltInType(
	std::shared_ptr<demangler::borland::BuiltInTypeNode> typeNode)
{
	assert(typeNode && "Node cannot be null");

	std::string typeName = typeNode->typeName();    // name without qualifiers

	if (typeName == "void") {
		return ctypes::VoidType::create();
	}

	if (typeName == "wchar_t"
		|| typeName == "bool"
		|| typeName == "char16_t"
		|| typeName == "char32_t") {
		return ctypes::IntegralType::create(
			context,
			typeName,
			getBitWidth(typeName),
			toSigness(typeName));
	}

	return ctypes::UnknownType::create();    // non from above
}

std::shared_ptr<ctypes::PointerType> BorlandToCtypesParser::parsePointerType(
	std::shared_ptr<demangler::borland::PointerTypeNode> pointerNode)
{
	assert(pointerNode && "Node cannot be null");

	auto pointeeNode = pointerNode->pointee();
	assert(pointeeNode && "Invalid AST, reference has to have valid type attached");

	auto pointeeType = parseType(std::static_pointer_cast<retdec::demangler::borland::TypeNode>(pointeeNode));
	auto bitWidth = getBitWidth("ptr_t");

	return ctypes::PointerType::create(context, pointeeType, bitWidth);
}

/*
 * @brief Parses L-value reference nodes to ctypes::ReferenceType.
 */
std::shared_ptr<ctypes::Type> BorlandToCtypesParser::parseReferenceType(
	std::shared_ptr<demangler::borland::ReferenceTypeNode> referenceNode)
{
	assert(referenceNode && "Node cannot be null");

	auto pointeeNode = referenceNode->pointee();
	assert(pointeeNode && "Invalid AST, reference has to have valid type attached");

	auto pointeeType = parseType(std::static_pointer_cast<retdec::demangler::borland::TypeNode>(pointeeNode));
	auto bitWidth = getBitWidth("ptr_t");

	return ctypes::ReferenceType::create(context, pointeeType, bitWidth);
}

/*
 * @brief Parses R-value reference nodes to ctypes::ReferenceType.
 */
std::shared_ptr<ctypes::Type> BorlandToCtypesParser::parseRReferenceType(
	std::shared_ptr<demangler::borland::RReferenceTypeNode> rreferenceNode)
{
	assert(rreferenceNode && "Node cannot be null");

	auto pointeeNode = rreferenceNode->pointee();
	assert(pointeeNode && "Invalid AST, reference has to have valid type attached");

	auto pointeeType = parseType(std::static_pointer_cast<retdec::demangler::borland::TypeNode>(pointeeNode));
	auto bitWidth = getBitWidth("ptr_t");

	// from ctypes point of view rvalue reference is the same as lvalue reference
	return ctypes::ReferenceType::create(context, pointeeType, bitWidth);
}

std::shared_ptr<ctypes::NamedType> BorlandToCtypesParser::parseNamedType(
	std::shared_ptr<retdec::demangler::borland::NamedTypeNode> namedTypeNode)
{
	assert(namedTypeNode && "Node cannot be null");

	std::string name = namedTypeNode->name()->str();    // name without qualifiers
	return ctypes::NamedType::create(context, name);
}

ctypes::Function::Parameters BorlandToCtypesParser::parseFuncParameters(
	std::shared_ptr<retdec::demangler::borland::NodeArray> paramsNode)
{
	ctypes::Function::Parameters parameters{};
	if (paramsNode == nullptr) {
		return parameters;
	}

	for (unsigned i = 0; i < paramsNode->size(); ++i) {
		auto paramNode = std::static_pointer_cast<demangler::borland::TypeNode>(paramsNode->get(i));
		auto type = parseType(paramNode);
		auto param = ctypes::Parameter("", type);    // name of parameter is not known, it is generated later
		parameters.emplace_back(param);
	}

	return parameters;
}

ctypes::FunctionType::Parameters BorlandToCtypesParser::parseFuncTypeParameters(
	std::shared_ptr<retdec::demangler::borland::NodeArray> paramsNode)
{
	ctypes::FunctionType::Parameters parameters{};
	if (paramsNode == nullptr) {
		return parameters;
	}

	for (unsigned i = 0; i < paramsNode->size(); ++i) {
		auto paramNode = std::static_pointer_cast<demangler::borland::TypeNode>(paramsNode->get(i));
		auto type = parseType(paramNode);
		parameters.emplace_back(type);
	}

	return parameters;
}

ctypes::CallConvention BorlandToCtypesParser::parseCallConvention(retdec::demangler::borland::CallConv callConv)
{
	switch (callConv) {
	case demangler::borland::CallConv::cc_cdecl:
		return ctypes::CallConvention("cdecl");
	case demangler::borland::CallConv::cc_stdcall:
		return ctypes::CallConvention("stdcall");
	case demangler::borland::CallConv::cc_fastcall:
		return ctypes::CallConvention("fastcall");
	case demangler::borland::CallConv::cc_pascal:
		return ctypes::CallConvention("pascal");
	default:
		return ctypes::CallConvention("unknown");	// should not happen in borland
	}
}

std::shared_ptr<ctypes::FunctionType> BorlandToCtypesParser::parsefuncType(
	std::shared_ptr<retdec::demangler::borland::FunctionTypeNode> funcTypeNode)
{
	std::shared_ptr<ctypes::Type> returnType = parseType(funcTypeNode->retType());
	ctypes::FunctionType::Parameters parameters = parseFuncTypeParameters(funcTypeNode->params());
	ctypes::CallConvention callConvention = parseCallConvention(funcTypeNode->callConv());
	ctypes::Function::VarArgness varArgness = toVarArgness(funcTypeNode->isVarArg());

	return ctypes::FunctionType::create(context, returnType, parameters, callConvention, varArgness);
}

/*
 * @brief Parses Array type nodes to ctypes::ArrayType.
 */
std::shared_ptr<ctypes::ArrayType> BorlandToCtypesParser::parseArrayType(
	std::shared_ptr<retdec::demangler::borland::ArrayNode> arrayTypeNode)
{
	ctypes::ArrayType::Dimensions dimensions;

	// Arrays are in AST stored recoursively.
	auto pointee = arrayTypeNode->pointee();
	dimensions.emplace_back(arrayTypeNode->size());
	while (pointee->kind() == Kind::KArrayNode) {
		dimensions.emplace_back(std::static_pointer_cast<demangler::borland::ArrayNode>(pointee)->size());
		pointee = std::static_pointer_cast<demangler::borland::ArrayNode>(pointee)->pointee();
	}

	auto type = parseType(std::static_pointer_cast<demangler::borland::TypeNode>(pointee));

	return ctypes::ArrayType::create(context, type, dimensions);
}

} // demangler
} // retdec

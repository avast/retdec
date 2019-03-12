#include <cassert>

#include "retdec/ctypesparser/borland_ast_ctypes_parser.h"
#include "retdec/ctypes/type.h"
#include "retdec/ctypes/function.h"
#include "retdec/ctypes/parameter.h"
#include "retdec/ctypes/unknown_type.h"
#include "retdec/ctypes/integral_type.h"
#include "retdec/ctypes/floating_point_type.h"
#include "retdec/ctypes/pointer_type.h"
#include "retdec/ctypes/reference_type.h"
#include "retdec/ctypes/void_type.h"

using Kind = retdec::demangler::borland::Node::Kind;

namespace retdec {
namespace ctypesparser {

namespace {

inline ctypes::IntegralType::Signess toSigness(bool isUnsigned)
{
	return isUnsigned ? ctypes::IntegralType::Signess::Unsigned : ctypes::IntegralType::Signess::Signed;
}

ctypes::IntegralType::Signess toSigness(const std::string &typeName)	// TODO config
{
	if (typeName.substr(0, 9) == "unsigned ") {
		return ctypes::IntegralType::Signess::Unsigned;
	}

	if (typeName.substr(0, 4) == "char" || typeName == "wchar_t") {
		return ctypes::IntegralType::Signess::Unsigned;
	}

	return ctypes::IntegralType::Signess::Signed;
}

}	// anonymous namespace

BorlandToCtypesParser::BorlandToCtypesParser() : CTypesParser() {}

bool BorlandToCtypesParser::parseInto(
	std::shared_ptr<retdec::demangler::borland::Node> ast,
	std::unique_ptr<retdec::ctypes::Module> &module,
	const TypeWidths &typeWidths,
	const TypeSignedness &typeSignedness,
	const retdec::ctypes::CallConvention &callConvention)
{
	assert(ast && "Ast cannot be null");

	context = module->getContext();
	defaultCallConv = callConvention;
	this->typeWidths = typeWidths;
	this->typeSignedness = typeSignedness;

	switch (ast->kind()) {
	case Kind::KFunction: {
		auto func = parseFunction(std::static_pointer_cast<demangler::borland::FunctionNode>(ast));
		if (func) {
			module->addFunction(func);
			return true;
		}
		break;
	}
	default:
		break;
	}

	return false;
}

std::shared_ptr<ctypes::IntegralType> BorlandToCtypesParser::createIntegral(const std::string &typeName)
{
	auto bitWidth = typeWidths[typeName];
	ctypes::IntegralType::Signess signedness = typeSignedness[typeName];

	return ctypes::IntegralType::create(context, typeName, bitWidth, signedness);
}

std::shared_ptr<retdec::ctypes::Function> BorlandToCtypesParser::parseFunction(std::shared_ptr<demangler::borland::FunctionNode> function)
{
	assert(function && function->name() && "Violated precondition");

	std::string name = function->name()->str();

	auto funcType = function->funcType();

	std::shared_ptr<ctypes::Type> returnType = parseType(funcType->retType());
	ctypes::Function::Parameters parameters = parseFuncParameters(funcType->params());
	ctypes::CallConvention callConvention = parseCallConvention(funcType->callConv());
	ctypes::Function::VarArgness varArgness = parseVarArgness(funcType->isVarArg());

	return ctypes::Function::create(context, name, returnType, parameters, callConvention, varArgness);
}

std::shared_ptr<ctypes::Type> BorlandToCtypesParser::parseType(std::shared_ptr<retdec::demangler::borland::TypeNode> typeNode)
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
		default:
			break;
		}
	}

	return std::static_pointer_cast<ctypes::Type>(ctypes::UnknownType::create());
}

std::shared_ptr<ctypes::IntegralType> BorlandToCtypesParser::parseIntegralType(
	std::shared_ptr<retdec::demangler::borland::IntegralTypeNode> integralNode)
{
	assert(integralNode && "Node cannot be null");

	std::string name = integralNode->typeName();	// no qualifiers
	unsigned bitWidth = typeWidths[integralNode->typeName()];
	ctypes::IntegralType::Signess signess = toSigness(integralNode->isUnsigned());

	return ctypes::IntegralType::create(context, name, bitWidth, signess);
}

std::shared_ptr<ctypes::FloatingPointType> BorlandToCtypesParser::parseFloatingPointType(
	std::shared_ptr<retdec::demangler::borland::FloatTypeNode> floatNode)
{
	assert(floatNode && "Node cannot be null");

	std::string name = floatNode->typeName();	// no qualifiers
	unsigned bitWidth = typeWidths[floatNode->typeName()];

	return ctypes::FloatingPointType::create(context, name, bitWidth);
}

std::shared_ptr<ctypes::IntegralType> BorlandToCtypesParser::parseCharType(
	std::shared_ptr<retdec::demangler::borland::CharTypeNode> charNode)
{
	assert(charNode && "Node cannot be null");

	std::string name = charNode->typeName();	// no qualifiers
	unsigned bitWidth = typeWidths[name];
	ctypes::IntegralType::Signess signess = toSigness(name);

	return ctypes::IntegralType::create(context, name, bitWidth, signess);
}

std::shared_ptr<ctypes::Type> BorlandToCtypesParser::parseBuiltInType(
	std::shared_ptr<retdec::demangler::borland::BuiltInTypeNode> typeNode)
{
	assert(typeNode && "Node cannot be null");

	std::string typeName = typeNode->typeName();	// no qualifiers

	if (typeName == "void") {
		return ctypes::VoidType::create();
	}

	if (typeName == "wchar_t"
		|| typeName == "bool"
		|| typeName == "char16_t"
		|| typeName == "char32_t") {
		return std::static_pointer_cast<ctypes::Type>(createIntegral(typeName));
	}

	return ctypes::UnknownType::create();    // non from above
}

std::shared_ptr<ctypes::PointerType> BorlandToCtypesParser::parsePointerType(
	std::shared_ptr<retdec::demangler::borland::PointerTypeNode> pointerNode)
{
	assert(pointerNode && "Node cannot be null");

	auto pointeeNode = pointerNode->pointee();    // always will be valid pointer and type
	auto pointeeType = parseType(std::static_pointer_cast<retdec::demangler::borland::TypeNode>(pointeeNode));
	auto bitWidth = typeWidths["pointer"];

	return ctypes::PointerType::create(context, pointeeType, bitWidth);
}

std::shared_ptr<ctypes::Type> BorlandToCtypesParser::parseReferenceType(
	std::shared_ptr<retdec::demangler::borland::ReferenceTypeNode> referenceNode)
{
	assert(referenceNode && "Node cannot be null");

	auto pointeeNode = referenceNode->pointee();    // always will be valid pointer and type
	auto pointeeType = parseType(std::static_pointer_cast<retdec::demangler::borland::TypeNode>(pointeeNode));
	auto bitWidth = typeWidths["reference"];

	return ctypes::ReferenceType::create(context, pointeeType, bitWidth);
}

std::shared_ptr<ctypes::Type> BorlandToCtypesParser::parseRReferenceType(
	std::shared_ptr<retdec::demangler::borland::RReferenceTypeNode> rreferenceNode)
{
	assert(rreferenceNode && "Node cannot be null");

	return std::static_pointer_cast<ctypes::Type>(ctypes::UnknownType::create());    // TODO rreference
}

std::shared_ptr<ctypes::NamedType> BorlandToCtypesParser::parseNamedType(
	std::shared_ptr<retdec::demangler::borland::NamedTypeNode> namedTypeNode)
{
	assert(namedTypeNode && "Node cannot be null");

	std::string name = namedTypeNode->name()->str();	// no qualifiers
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
		auto param = ctypes::Parameter("", type);
		parameters.emplace_back(param);
	}
	return {parameters};
}

ctypes::CallConvention BorlandToCtypesParser::parseCallConvention(retdec::demangler::borland::CallConv callConv)
{
	switch (callConv) {
	case demangler::borland::CallConv::cdecl:
		return ctypes::CallConvention("cdecl");
	case demangler::borland::CallConv::stdcall:
		return ctypes::CallConvention("stdcall");
	case demangler::borland::CallConv::fastcall:
		return ctypes::CallConvention("fastcall");
	case demangler::borland::CallConv::pascal:
		return ctypes::CallConvention("pascal");
	default:
		return ctypes::CallConvention();
	}
}

ctypes::FunctionType::VarArgness BorlandToCtypesParser::parseVarArgness(bool isVarArg)
{
	if (isVarArg) {
		return ctypes::FunctionType::VarArgness::IsVarArg;
	} else {
		return ctypes::FunctionType::VarArgness::IsNotVarArg;
	}
}

}    // ctypesparser
}    // retdec

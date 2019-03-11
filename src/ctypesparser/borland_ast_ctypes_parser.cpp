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
namespace borland_ast {

namespace {

inline ctypes::IntegralType::Signess toSigness(bool isUnsigned)
{
	return isUnsigned ? ctypes::IntegralType::Signess::Unsigned : ctypes::IntegralType::Signess::Signed;
}

ctypes::IntegralType::Signess toSigness(
	demangler::borland::ThreeStateSignedness signedness)
{
	switch (signedness) {    // TODO config
	case demangler::borland::ThreeStateSignedness::unsigned_char:
		return ctypes::IntegralType::Signess::Unsigned;
	case demangler::borland::ThreeStateSignedness::signed_char:
		return ctypes::IntegralType::Signess::Signed;
	default:
		return ctypes::IntegralType::Signess::Unsigned;
	}
}

}

BorlandToCtypesParser::BorlandToCtypesParser() :
	_status(init), _context(nullptr), defaultBitWidth(0), defaultCallConv(ctypes::CallConvention())
{
	typeWidths = {
		{"void", 0},
		{"bool", 1},
		{"char", 8},
		{"wchar_t", 32},
		{"short", 16},
		{"int", 32},
		{"long", 64},
		{"long long", 64},
		{"float", 32},
		{"double", 64},
		{"long double", 96},
		{"pointer", 32},
		{"reference", 32}
	};

	typeSignedness = {
		{"wchar_t", ctypes::IntegralType::Signess::Unsigned},
		{"char16_t", ctypes::IntegralType::Signess::Unsigned},
		{"char32_t", ctypes::IntegralType::Signess::Unsigned}
	};
}

BorlandToCtypesParser::Status BorlandToCtypesParser::status()
{
	return _status;
}

void BorlandToCtypesParser::parseInto(
	std::shared_ptr<retdec::demangler::borland::Node> ast,
	retdec::ctypes::Module &module)
{
	assert(ast && "Ast cannot be null");

	_context = module.getContext();

	switch (ast->kind()) {
	case Kind::KFunction: {
		auto func = parseFunction(std::static_pointer_cast<demangler::borland::FunctionNode>(ast));
		if (func) {
			module.addFunction(func);
			_status = success;
		}
		break;
	}
	default:
		_status = invalid_ast;
	}
}

std::shared_ptr<ctypes::IntegralType> BorlandToCtypesParser::createIntegral(const std::string &typeName)
{
	auto bitWidth = typeWidths[typeName];
	ctypes::IntegralType::Signess signedness = typeSignedness[typeName];

	return ctypes::IntegralType::create(_context, typeName, bitWidth, signedness);
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

	return ctypes::Function::create(_context, name, returnType, parameters, callConvention, varArgness);
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
		default:
			break;
		}
	}

	return std::static_pointer_cast<ctypes::Type>(ctypes::UnknownType::create());
}

std::shared_ptr<ctypes::IntegralType> BorlandToCtypesParser::parseIntegralType(
	std::shared_ptr<retdec::demangler::borland::IntegralTypeNode> integralNode)
{
	std::string name = integralNode->str();
	unsigned bitWidth = typeWidths[integralNode->typeName()];
	ctypes::IntegralType::Signess signess = toSigness(integralNode->isUnsigned());

	return ctypes::IntegralType::create(_context, name, bitWidth, signess);
}

std::shared_ptr<ctypes::FloatingPointType> BorlandToCtypesParser::parseFloatingPointType(
	std::shared_ptr<retdec::demangler::borland::FloatTypeNode> floatNode)
{
	std::string name = floatNode->str();
	unsigned bitWidth = typeWidths[floatNode->typeName()];

	return ctypes::FloatingPointType::create(_context, name, bitWidth);
}

std::shared_ptr<ctypes::IntegralType> BorlandToCtypesParser::parseCharType(
	std::shared_ptr<retdec::demangler::borland::CharTypeNode> charNode)
{
	std::string name = charNode->str();
	unsigned bitWidth = typeWidths[charNode->typeName()];
	ctypes::IntegralType::Signess signess = toSigness(charNode->signedness());

	return ctypes::IntegralType::create(_context, name, bitWidth, signess);
}

std::shared_ptr<ctypes::Type> BorlandToCtypesParser::parseBuiltInType(
	std::shared_ptr<retdec::demangler::borland::BuiltInTypeNode> typeNode)
{
	std::string typeName = typeNode->typeName();

	if (typeName == "void") {
		return ctypes::VoidType::create();
	}

	if (typeName == "wchar_t"
		|| typeName == "bool"
		|| typeName == "char16_t"
		|| typeName == "char32_t") {
		return std::static_pointer_cast<ctypes::Type>(createIntegral(typeName));
	}

	return ctypes::UnknownType::create();    // else
}

std::shared_ptr<ctypes::PointerType> BorlandToCtypesParser::parsePointerType(
	std::shared_ptr<retdec::demangler::borland::PointerTypeNode> pointerNode)
{
	auto pointeeNode = pointerNode->pointee();    // always will be valid pointer and type
	auto pointeeType = parseType(std::static_pointer_cast<retdec::demangler::borland::TypeNode>(pointeeNode));
	auto bitWidth = typeWidths["pointer"];

	return ctypes::PointerType::create(_context, pointeeType, bitWidth);
}

std::shared_ptr<ctypes::Type> BorlandToCtypesParser::parseReferenceType(
	std::shared_ptr<retdec::demangler::borland::ReferenceTypeNode> referenceNode)
{
	auto pointeeNode = referenceNode->pointee();    // always will be valid pointer and type
	auto pointeeType = parseType(std::static_pointer_cast<retdec::demangler::borland::TypeNode>(pointeeNode));
	auto bitWidth = typeWidths["reference"];

	return ctypes::ReferenceType::create(_context, pointeeType, bitWidth);
}

std::shared_ptr<ctypes::Type> BorlandToCtypesParser::parseRReferenceType(
	std::shared_ptr<retdec::demangler::borland::RReferenceTypeNode> rreferenceNode)
{
	return std::static_pointer_cast<ctypes::Type>(ctypes::UnknownType::create());    // TODO rreference
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

}    // borland_ast
}    // ctypesparser
}    // retdec

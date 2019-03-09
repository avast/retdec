#include <cassert>

#include "llvm/Demangle/borland_ast.h"
#include "llvm/Demangle/borland_ast_types.h"
#include "retdec/ctypes/type.h"
#include "retdec/ctypes/function.h"
#include "retdec/ctypes/unknown_type.h"
#include "retdec/ctypes/integral_type.h"
#include "retdec/ctypes/floating_point_type.h"
#include "retdec/ctypesparser/borland_ast_ctypes_parser.h"

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
	case demangler::borland::ThreeStateSignedness::no_prefix :
		return ctypes::IntegralType::Signess::Unsigned;
	case demangler::borland::ThreeStateSignedness::unsigned_char:
		return ctypes::IntegralType::Signess::Unsigned;
	case demangler::borland::ThreeStateSignedness::signed_char:
		return ctypes::IntegralType::Signess::Signed;
	}
}

}

BorlandToCtypesParser::BorlandToCtypesParser() :
	_status(init), _context(nullptr) {}

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

std::shared_ptr<retdec::ctypes::Function> BorlandToCtypesParser::parseFunction(std::shared_ptr<demangler::borland::FunctionNode> function)
{
	std::string name = function->name()->str();    // TODO null on name()

	auto funcType = function->funcType();

	std::shared_ptr<ctypes::Type> returnType = parseType(funcType->retType());
	ctypes::Function::Parameters parameters = parseFuncParameters(funcType->params());
	ctypes::CallConvention callConvention = parseCallConvention(funcType->callConv());
	ctypes::Function::VarArgness varArgness = parseVarArgness(funcType->isVarArg());

//	// TODO check status
//
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
	unsigned bitWidth = 32;    // TODO
	ctypes::IntegralType::Signess signess = toSigness(integralNode->isUnsigned());

	return ctypes::IntegralType::create(_context, name, bitWidth, signess);
}

std::shared_ptr<ctypes::FloatingPointType> BorlandToCtypesParser::parseFloatingPointType(
	std::shared_ptr<retdec::demangler::borland::FloatTypeNode> floatNode)
{
	std::string name = floatNode->str();
	unsigned bitWidth = 32;    // TODO

	return ctypes::FloatingPointType::create(_context, name, bitWidth);
}

std::shared_ptr<ctypes::IntegralType> BorlandToCtypesParser::parseCharType(
	std::shared_ptr<retdec::demangler::borland::CharTypeNode> charNode)
{
	std::string name = charNode->str();
	unsigned bitWidth = 8;    // TODO
	ctypes::IntegralType::Signess signess = toSigness(charNode->signedness());

	return ctypes::IntegralType::create(_context, name, bitWidth, signess);
}

ctypes::Function::Parameters BorlandToCtypesParser::parseFuncParameters(
	std::shared_ptr<retdec::demangler::borland::NodeArray> paramsNode)
{
	ctypes::Function::Parameters parameters{};
	if (paramsNode == nullptr) {
		return parameters;
	}

// TODO
// 	for (param: paramsNode->params) {
//		parameters.emplace_back(parseType(param));
//	}
	return parameters;
}

ctypes::CallConvention BorlandToCtypesParser::parseCallConvention(retdec::demangler::borland::CallConv callConv)
{
	// TODO
	return ctypes::CallConvention();
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

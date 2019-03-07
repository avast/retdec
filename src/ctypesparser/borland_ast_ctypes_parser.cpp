#include <cassert>

#include "retdec/ctypesparser/borland_ast_ctypes_parser.h"
#include "llvm/Demangle/borland_ast.h"
#include "retdec/ctypes/type.h"
#include "retdec/ctypes/function.h"
#include "retdec/ctypes/unknown_type.h"

using Kind = retdec::demangler::borland::Node::Kind;

namespace retdec {
namespace ctypesparser {
namespace borland_ast {

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
//	ctypes::Function::Parameters parameters = parseFuncParameters(funcType->params());
//	ctypes::CallConvention callConvention = parseCallConvention(funcNode->callConv());
//	ctypes::Function::VarArgness varArgness = parseVarArgness(funcNode->isVarArg());
//
//	// TODO check status
//
//	return ctypes::Function::create(_context, name, returnType, Parameters, callConvention, varArgness);
	return nullptr;
}

std::shared_ptr<ctypes::Type> BorlandToCtypesParser::parseType(std::shared_ptr<retdec::demangler::borland::TypeNode> typeNode)
{
	if (typeNode == nullptr) {
		return std::static_pointer_cast<ctypes::Type>(ctypes::UnknownType::create());
	}

	switch (typeNode->kind()) {
	case Kind::KIntegralType:

	default:
		return std::static_pointer_cast<ctypes::Type>(ctypes::UnknownType::create());
	}

}

//std::shared_ptr<ctypes::IntegralType> BorlandToCtypesParser::parseIntegralType(std::shared_ptr<retdec::demangler::borland::TypeNode> integralNode)
//{
//
//}

//Parameters BorlandToCtypesParser::parseFuncParameters(std::shared_ptr<retdec::demangler::borland::ArrayNode> &paramsNode)
//{
//	return nullptr;
////	if (paramsNode == nullptr) {
////		return
////	}
//}

}    // borland_ast
}    // ctypesparser
}    // retdec

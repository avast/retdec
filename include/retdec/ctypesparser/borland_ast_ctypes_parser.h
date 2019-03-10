#ifndef RETDEC_BORLAND_AST_CTYPES_PARSER_H
#define RETDEC_BORLAND_AST_CTYPES_PARSER_H

#include "retdec/demangler/borland_ast.h"
#include "retdec/demangler/borland_ast_types.h"
#include "retdec/ctypes/module.h"
#include "retdec/ctypes/context.h"
#include "retdec/ctypes/function.h"
#include "retdec/ctypes/type.h"
#include "retdec/ctypes/integral_type.h"
#include "retdec/ctypes/pointer_type.h"
#include "retdec/ctypes/floating_point_type.h"

namespace retdec {
namespace ctypesparser {
namespace borland_ast {

class BorlandToCtypesParser
{
public:
	enum Status : u_char
	{
		success = 0,
		init,
		invalid_ast,
	};

public:
	BorlandToCtypesParser();

	Status status();

	void parseInto(
		std::shared_ptr<demangler::borland::Node> ast,
		retdec::ctypes::Module &module);

private:
	std::shared_ptr<ctypes::Function> parseFunction(std::shared_ptr<demangler::borland::FunctionNode> function);
	std::shared_ptr<ctypes::Type> parseType(std::shared_ptr<demangler::borland::TypeNode> typeNode);
//	std::shared_ptr<ctypes::IntegralType> parseIntegralType(std::shared_ptr<demangler::borland::IntegralTypeNode> integralNode);
//	std::shared_ptr<ctypes::FloatingPointType> parseFloatingPointType(std::shared_ptr<demangler::borland::FloatTypeNode> floatNode);
//	std::shared_ptr<ctypes::IntegralType> parseCharType(std::shared_ptr<demangler::borland::CharTypeNode> charNode);
//	std::shared_ptr<ctypes::Type> parseBuiltInType(std::shared_ptr<demangler::borland::BuiltInTypeNode> typeNode);
//	std::shared_ptr<ctypes::PointerType> parsePointerType(std::shared_ptr<demangler::borland::PointerTypeNode> pointerNode);
//	std::shared_ptr<ctypes::Type> parseReferenceType(std::shared_ptr<demangler::borland::ReferenceTypeNode> referenceNode);
//	std::shared_ptr<ctypes::Type> parseRReferenceType(std::shared_ptr<demangler::borland::RReferenceTypeNode> referenceNode);
	ctypes::Function::Parameters parseFuncParameters(std::shared_ptr<demangler::borland::NodeArray> paramsNode);
	ctypes::CallConvention parseCallConvention(demangler::borland::CallConv callConv);
	ctypes::FunctionType::VarArgness parseVarArgness(bool isVarArg);

private:
	Status _status;
	std::shared_ptr<ctypes::Context> _context;
};

}    // borland_ast
}    // ctypesparser
}    // retdec

#endif //RETDEC_BORLAND_AST_CTYPES_PARSER_H

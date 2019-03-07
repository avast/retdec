#ifndef RETDEC_BORLAND_AST_CTYPES_PARSER_H
#define RETDEC_BORLAND_AST_CTYPES_PARSER_H

#include "llvm/Demangle/borland_ast.h"
#include "llvm/Demangle/borland_ast_types.h"
#include "retdec/ctypes/module.h"
#include "retdec/ctypes/context.h"
#include "retdec/ctypes/function.h"
#include "retdec/ctypes/type.h"
#include "retdec/ctypes/integral_type.h"

class Parameters;
class VarArgness;

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
		std::shared_ptr <demangler::borland::Node> ast,
		retdec::ctypes::Module &module);

private:
	std::shared_ptr <ctypes::Function> parseFunction(std::shared_ptr <demangler::borland::FunctionNode> function);
	std::shared_ptr <ctypes::Type> parseType(std::shared_ptr <demangler::borland::TypeNode> typeNode);
	std::shared_ptr <ctypes::IntegralType> parseIntegralType(std::shared_ptr <demangler::borland::TypeNode> integralNode);
	Parameters parseFuncParameters(std::shared_ptr <demangler::borland::ArrayNode> &paramsNode);
	ctypes::CallConvention parseCallConvention(demangler::borland::CallConv &callConv);
	VarArgness parseVarArgness(bool isVarArg);

private:
	Status _status;
	std::shared_ptr <ctypes::Context> _context;
};

}	// borland_ast
}	// ctypesparser
}	// retdec

#endif //RETDEC_BORLAND_AST_CTYPES_PARSER_H

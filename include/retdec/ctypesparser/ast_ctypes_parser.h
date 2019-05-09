#ifndef RETDEC_AST_CTYPES_PARSER_H
#define RETDEC_AST_CTYPES_PARSER_H

#include "retdec/ctypesparser/ctypes_parser.h"

namespace retdec {
namespace ctypesparser {

class AstToCtypesParser: public CTypesParser {
public:
	AstToCtypesParser () = default;

protected:
	unsigned toBitWidth(const std::string &typeName) const;

	ctypes::IntegralType::Signess toSigness(bool isUnsigned) const;

	ctypes::IntegralType::Signess toSigness(const std::string &typeName) const;

	ctypes::FunctionType::VarArgness toVarArgness(bool isVarArg) const;
};

}
}

#endif //RETDEC_AST_CTYPES_PARSER_H

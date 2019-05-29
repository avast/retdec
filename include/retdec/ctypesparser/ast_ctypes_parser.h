/**
* @file include/retdec/ctypesparser/ast_ctypes_parser.h
* @brief Base class for all AST to ctypes parsers.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_AST_CTYPES_PARSER_H
#define RETDEC_AST_CTYPES_PARSER_H

#include "retdec/ctypesparser/ctypes_parser.h"

namespace retdec {
namespace ctypesparser {

/*
 * Base class for all AST to ctypes parsers.
 */
class AstToCtypesParser: public CTypesParser {
public:
	AstToCtypesParser () = default;

protected:
	unsigned getBitWidth(const std::string &typeName) const;

	ctypes::IntegralType::Signess toSigness(bool isUnsigned) const;

	ctypes::IntegralType::Signess toSigness(const std::string &typeName) const;

	ctypes::FunctionType::VarArgness toVarArgness(bool isVarArg) const;
};

}
}

#endif //RETDEC_AST_CTYPES_PARSER_H

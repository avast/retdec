#ifndef RETDEC_AST_CTYPES_PARSER_H
#define RETDEC_AST_CTYPES_PARSER_H

#include "retdec/ctypesparser/ctypes_parser.h"

namespace retdec {
namespace ctypesparser {

class AstToCtypesParser: public CTypesParser {
public:
	AstToCtypesParser () = default;

//protected:
	ctypes::IntegralType::Signess toSigness(bool isUnsigned);

	ctypes::IntegralType::Signess toSigness(const std::string &typeName);
};

}
}

#endif //RETDEC_AST_CTYPES_PARSER_H

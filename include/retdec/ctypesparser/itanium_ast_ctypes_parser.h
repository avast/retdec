#ifndef RETDEC_ITANIUM_AST_CTYPES_PARSER_H
#define RETDEC_ITANIUM_AST_CTYPES_PARSER_H

#include "retdec/ctypesparser/ast_ctypes_parser.h"
#include "retdec/ctypes/array_type.h"
#include "retdec/ctypes/module.h"
#include "retdec/ctypes/context.h"
#include "retdec/ctypes/function.h"
#include "retdec/ctypes/type.h"
#include "retdec/ctypes/integral_type.h"
#include "retdec/ctypes/named_type.h"
#include "retdec/ctypes/pointer_type.h"
#include "retdec/ctypes/floating_point_type.h"
#include "retdec/ctypesparser/ast_ctypes_parser.h"

namespace llvm {
namespace itanium_demangle {
class Node;
class FunctionEncoding;
}
}

namespace retdec {
namespace ctypesparser {

class ItaniumAstCtypesParser: public AstToCtypesParser {
public:
	ItaniumAstCtypesParser() = default;

	bool parseInto(
		const llvm::itanium_demangle::Node *ast,
		std::unique_ptr<retdec::ctypes::Module> &module,
		const TypeWidths &typeWidths = {},
		const TypeSignedness &typeSignedness = {},
		const retdec::ctypes::CallConvention &callConvention = retdec::ctypes::CallConvention());

private:
	std::shared_ptr<ctypes::Function> parseFunction(const llvm::itanium_demangle::FunctionEncoding *functionEncodingNode);
	std::string parseFunctionName(const llvm::itanium_demangle::Node *node);
	std::shared_ptr<ctypes::Type> parseType(const llvm::itanium_demangle::Node *typeNode);
};

}
}

#endif //RETDEC_ITANIUM_AST_CTYPES_PARSER_H

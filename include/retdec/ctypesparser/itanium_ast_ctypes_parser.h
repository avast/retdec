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
class FunctionEncoding;
class FunctionType;
class NameType;
class NodeArray;
class Node;
class PointerType;
class ReferenceType;
class ArrayType;
class NodeOrString;
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
	ctypes::Function::Parameters parseFunctionParameters(
		llvm::itanium_demangle::NodeArray node, bool &isVarArg);
	std::shared_ptr<ctypes::Type> parseType(const llvm::itanium_demangle::Node *typeNode);
	std::shared_ptr<ctypes::IntegralType> parseIntegralType(const std::string &name);
	std::shared_ptr<ctypes::FloatingPointType> parseFloatingPointType(const std::string &name);
	std::shared_ptr<ctypes::PointerType> parsePointer(const llvm::itanium_demangle::PointerType *typeNode);
	std::shared_ptr<ctypes::ReferenceType> parseReference(const llvm::itanium_demangle::ReferenceType *typeNode);
	std::shared_ptr<ctypes::Type> parseNameTypeNode(const llvm::itanium_demangle::NameType *nameTypeNode);
	std::shared_ptr<ctypes::ArrayType> parseArrayType(const llvm::itanium_demangle::ArrayType *typeNode);
	unsigned parseDimension(const llvm::itanium_demangle::NodeOrString *dimensions);
	std::shared_ptr<ctypes::FunctionType> parseFuntionType(const llvm::itanium_demangle::FunctionType *typeNode);
	ctypes::FunctionType::Parameters parseFuncTypeParameters(const llvm::itanium_demangle::NodeArray parameters,
																 bool &isVarArg);
};

}
}

#endif //RETDEC_ITANIUM_AST_CTYPES_PARSER_H

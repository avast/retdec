
#ifndef RETDEC_MS_AST_CTYPES_PARSER_H
#define RETDEC_MS_AST_CTYPES_PARSER_H

#include <llvm/Demangle/MicrosoftDemangleNodes.h>

#include "retdec/ctypes/module.h"
#include "retdec/ctypes/context.h"
#include "retdec/ctypes/function.h"
#include "retdec/ctypes/type.h"
#include "retdec/ctypes/integral_type.h"
#include "retdec/ctypes/named_type.h"
#include "retdec/ctypes/pointer_type.h"
#include "retdec/ctypes/floating_point_type.h"
#include "retdec/ctypesparser/ast_ctypes_parser.h"

namespace retdec {
namespace ctypesparser {

class MsToCtypesParser : public AstToCtypesParser
{
public:
	MsToCtypesParser() = default;

	std::shared_ptr<ctypes::Function> parseAsFunction(
		const std::string &mangledName,
		llvm::ms_demangle::SymbolNode *ast,
		std::unique_ptr<ctypes::Module> &module,
		const TypeWidths &typeWidths = {},
		const TypeSignedness &typeSignedness = {},
		unsigned defaultBitWidth = 0);

private:
	std::shared_ptr<ctypes::Function> parseFunction(
		const std::string &mangledName, llvm::ms_demangle::FunctionSymbolNode *functionSymbolNode);
	ctypes::CallConvention parseCallConvention(llvm::ms_demangle::CallingConv callConv);
	std::shared_ptr<ctypes::Type> parseType(llvm::ms_demangle::Node *typeNode);
	std::shared_ptr<ctypes::Type> parsePrimitiveType(llvm::ms_demangle::PrimitiveTypeNode *primitiveTypeNode);
	std::shared_ptr<ctypes::IntegralType> parseIntegralType(llvm::ms_demangle::PrimitiveTypeNode *integralTypeNode);
	std::shared_ptr<ctypes::FloatingPointType> parseFloatingPointType(llvm::ms_demangle::PrimitiveTypeNode *floatingPointTypeNode);
	ctypes::Function::Parameters parseFunctionParameters(llvm::ms_demangle::NodeArrayNode *parameters);
	std::shared_ptr<ctypes::Type> parsePointerType(llvm::ms_demangle::PointerTypeNode *typeNode);
	std::shared_ptr<ctypes::Type> parseNamedType(llvm::ms_demangle::Node *node);
	std::shared_ptr<ctypes::FunctionType> parseFuncType(llvm::ms_demangle::FunctionSignatureNode *funcSignature);
	ctypes::FunctionType::Parameters parseFuncTypeParameters(llvm::ms_demangle::NodeArrayNode *parameters);

	std::string getTypeName(llvm::ms_demangle::PrimitiveKind type) const;
};

}    // namespace ctypesparser
}    // namespace retdec

#endif //RETDEC_MS_AST_CTYPES_PARSER_H

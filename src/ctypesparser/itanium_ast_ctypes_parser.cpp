#include "llvm/Demangle/ItaniumDemangle.h"

#include "retdec/ctypes/module.h"
#include "retdec/ctypesparser/itanium_ast_ctypes_parser.h"

namespace retdec {
namespace ctypesparser {

namespace {

std::string printToString(const llvm::itanium_demangle::Node *node)
{

	llvm::itanium_demangle::OutputStream s;
	char *buf = nullptr;

	if (!node) {
		return {};
	}

	if (!initializeOutputStream(buf, nullptr, s, 1024)) {
		return {};
	}

	node->print(s);
	s += '\0';
	buf = s.getBuffer();

	std::string name(buf);
	free(buf);
	return name;
}

}    // anonymous namespace

using Kind = llvm::itanium_demangle::Node::Kind;

bool ItaniumAstCtypesParser::parseInto(
	const llvm::itanium_demangle::Node *ast,
	std::unique_ptr<retdec::ctypes::Module> &module,
	const retdec::ctypesparser::CTypesParser::TypeWidths &typeWidths,
	const retdec::ctypesparser::CTypesParser::TypeSignedness &typeSignedness,
	const retdec::ctypes::CallConvention &callConvention)
{
	assert(ast && "Ast cannot be null");

	context = module->getContext();
	defaultCallConv = callConvention;
	this->typeWidths = typeWidths;
	this->typeSignedness = typeSignedness;

	switch (ast->getKind()) {
	case Kind::KFunctionEncoding: {
		auto func = parseFunction(static_cast<const llvm::itanium_demangle::FunctionEncoding *>(ast));
		if (func) {
			module->addFunction(func);
			return true;
		}
		break;
	}
	default:
		break;
	}

	return false;
}

std::shared_ptr<ctypes::Function> ItaniumAstCtypesParser::parseFunction(
	const llvm::itanium_demangle::FunctionEncoding *functionEncodingNode)
{
	assert(functionEncodingNode && "Violated precondition.");

	std::string name = parseFunctionName(functionEncodingNode->getName());
	std::shared_ptr<ctypes::Type> returnType = parseType(functionEncodingNode->getReturnType());
}

std::string ItaniumAstCtypesParser::parseFunctionName(const llvm::itanium_demangle::Node *node)
{
	assert(node && "Violated precondition.");

	return printToString(node);
}

std::shared_ptr<ctypes::Type> ItaniumAstCtypesParser::parseType(
	const llvm::itanium_demangle::Node *typeNode)
{

}

}
}
#include "llvm/Demangle/ItaniumDemangle.h"

#include "retdec/utils/container.h"
#include "retdec/ctypes/module.h"
#include "retdec/ctypes/unknown_type.h"
#include "retdec/ctypes/type.h"
#include "retdec/ctypes/function.h"
#include "retdec/ctypes/parameter.h"
#include "retdec/ctypes/unknown_type.h"
#include "retdec/ctypes/integral_type.h"
#include "retdec/ctypes/floating_point_type.h"
#include "retdec/ctypes/pointer_type.h"
#include "retdec/ctypes/reference_type.h"
#include "retdec/ctypes/void_type.h"
#include "retdec/ctypesparser/itanium_ast_ctypes_parser.h"

namespace retdec {
namespace ctypesparser {

using Kind = llvm::itanium_demangle::Node::Kind;
using StringView = llvm::itanium_demangle::StringView;

namespace {

std::string toString(const llvm::itanium_demangle::Node *node)
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

inline std::string toString(const StringView &s)
{
	return {s.begin(), s.size()};
}

}    // anonymous namespace

std::shared_ptr<ctypes::Function> ItaniumAstCtypesParser::parseAsFunction(
	const llvm::itanium_demangle::Node *ast,
	std::shared_ptr<retdec::ctypes::Module> &module,
	const retdec::ctypesparser::CTypesParser::TypeWidths &typeWidths,
	const retdec::ctypesparser::CTypesParser::TypeSignedness &typeSignedness)
{
	assert(ast && "Ast cannot be null");

	context = module->getContext();
	this->typeWidths = typeWidths;
	this->typeSignedness = typeSignedness;

	if (ast->getKind() == Kind::KFunctionEncoding) {
		auto func = parseFunction(static_cast<const llvm::itanium_demangle::FunctionEncoding *>(ast));
		if (func) {
			module->addFunction(func);
			return func;
		}
	}

	return nullptr;
}

std::shared_ptr<ctypes::Function> ItaniumAstCtypesParser::parseFunction(
	const llvm::itanium_demangle::FunctionEncoding *functionEncodingNode)
{
	assert(functionEncodingNode && "Violated precondition.");

	std::string name = parseFunctionName(functionEncodingNode->getName());
	std::shared_ptr<ctypes::Type> returnType = parseType(functionEncodingNode->getReturnType());
	bool isVarArg = false;
	ctypes::Function::Parameters parameters =
		parseFunctionParameters(functionEncodingNode->getParams(), isVarArg);
	ctypes::Function::VarArgness varArgness = toVarArgness(isVarArg);
	ctypes::CallConvention callConvention = ctypes::CallConvention("unknown");    // calling convention is not mangled in names

	return ctypes::Function::create(context, name, returnType, parameters, callConvention, varArgness);
}

std::string ItaniumAstCtypesParser::parseFunctionName(const llvm::itanium_demangle::Node *node)
{
	assert(node && "Violated precondition.");

	return toString(node);
}

ctypes::Function::Parameters ItaniumAstCtypesParser::parseFunctionParameters(
	llvm::itanium_demangle::NodeArray node,
	bool &isVarArg)
{
	using Parameters = ctypes::Function::Parameters;

	Parameters parameters;

	for (size_t i = 0; i < node.size(); ++i) {
		auto type = parseType(node[i]);
		if (type->isNamed()
			&& std::static_pointer_cast<ctypes::NamedType>(type)->getName() == "...") {
			isVarArg = true;
		} else {
			auto parameter = ctypes::Parameter("param" + std::to_string(i), type);
			parameters.emplace_back(parameter);
		}
	}

	return parameters;
}

std::shared_ptr<ctypes::Type> ItaniumAstCtypesParser::parseType(
	const llvm::itanium_demangle::Node *typeNode)
{
	if (!typeNode) {
		return ctypes::UnknownType::create();
	}

	std::shared_ptr<ctypes::Type> parsedType;

	switch (typeNode->getKind()) {
	case Kind::KQualType:
		parsedType = parseType(static_cast<const llvm::itanium_demangle::QualType *>(typeNode)->getChild());
		break;
	case Kind::KPointerType:
		parsedType = parsePointer(static_cast<const llvm::itanium_demangle::PointerType *>(typeNode));
		break;
	case Kind::KReferenceType:
		parsedType = parseReference(static_cast<const llvm::itanium_demangle::ReferenceType *>(typeNode));
		break;
	case Kind::KNameType:
		parsedType = parseNameTypeNode(static_cast<const llvm::itanium_demangle::NameType *>(typeNode));
		break;
	case Kind::KArrayType:
		parsedType = parseArrayType(static_cast<const llvm::itanium_demangle::ArrayType *>(typeNode));
		break;
	case Kind::KFunctionType:
		parsedType = parseFuntionType(static_cast<const llvm::itanium_demangle::FunctionType *>(typeNode));
		break;
	default:
		parsedType = ctypes::UnknownType::create();
	}

	return parsedType;
}

std::shared_ptr<ctypes::IntegralType> ItaniumAstCtypesParser::parseIntegralType(const std::string &name)
{
	assert(!name.empty() && "Violated precondition.");

	unsigned bitWidth = utils::mapGetValueOrDefault(typeWidths, name, defaultBitWidth);
	ctypes::IntegralType::Signess signess = toSigness(name);

	return ctypes::IntegralType::create(context, name, bitWidth, signess);
}

std::shared_ptr<ctypes::FloatingPointType> ItaniumAstCtypesParser::parseFloatingPointType(
	const std::string &name)
{
	assert(!name.empty() && "Violated precondition.");

	unsigned bitWidth = utils::mapGetValueOrDefault(typeWidths, name, defaultBitWidth);

	return ctypes::FloatingPointType::create(context, name, bitWidth);
}

std::shared_ptr<ctypes::PointerType> ItaniumAstCtypesParser::parsePointer(
	const llvm::itanium_demangle::PointerType *typeNode)
{
	assert(typeNode && "Violated precondition.");

	auto pointee = parseType(typeNode->getPointee());
	unsigned bitWidth = utils::mapGetValueOrDefault(typeWidths, "pointer", defaultBitWidth);

	return ctypes::PointerType::create(context, pointee, bitWidth);
}

std::shared_ptr<ctypes::Type> ItaniumAstCtypesParser::parseReference(
	const llvm::itanium_demangle::ReferenceType *typeNode)
{
	assert(typeNode && "Violated precondition.");

	auto pointee = parseType(typeNode->getPointee());
	unsigned bitWidth = utils::mapGetValueOrDefault(typeWidths, "reference", defaultBitWidth);

	using RefrenceKind = llvm::itanium_demangle::ReferenceKind;
	if (typeNode->getReferenceKind() == RefrenceKind::LValue) {
		return ctypes::ReferenceType::create(context, pointee, bitWidth);
	} else {
		return ctypes::UnknownType::create();    // TODO r-value refrence
	}
}

std::shared_ptr<ctypes::Type> ItaniumAstCtypesParser::parseNameTypeNode(
	const llvm::itanium_demangle::NameType *nameTypeNode)
{
	assert(nameTypeNode && "Violated precondition.");

	std::string name = toString(nameTypeNode->getName());

	if (name == "void") {
		return ctypes::VoidType::create();
	}

	if (name == "wchar_t"
		|| name == "bool"
		|| name == "char"
		|| name == "signed char"
		|| name == "unsigned char"
		|| name == "char32_t"
		|| name == "char16_t"
		|| name == "short"
		|| name == "unsigned short"
		|| name == "int"
		|| name == "unsigned int"
		|| name == "long"
		|| name == "unsigned long"
		|| name == "long long"
		|| name == "unsigned long long"
		|| name == "__int128"
		|| name == "unsigned __int128") {
		return parseIntegralType(name);
	}

	if (name == "float"
		|| name == "double"
		|| name == "long double"
		|| name == "__float128") {
		return parseFloatingPointType(name);
	}

	if (name == "decimal64"
		|| name == "decimal128"
		|| name == "decimal32"
		|| name == "decimal16"
		|| name == "auto"
		|| name == "decltype(auto)"
		|| name == "std::nullptr_t") {
		return ctypes::UnknownType::create();    // TODO decimal support
	}

//	if (name == "...") return type with name "..."
	return ctypes::NamedType::create(context, name);
}

std::shared_ptr<ctypes::ArrayType> ItaniumAstCtypesParser::parseArrayType(
	const llvm::itanium_demangle::ArrayType *typeNode)
{
	using Dimensions = ctypes::ArrayType::Dimensions;

	Dimensions dimensions;
	dimensions.emplace_back(parseDimension(typeNode->getDimension()));

	const llvm::itanium_demangle::Node *arrayTypeNode = typeNode->getBase();
	while (arrayTypeNode->getKind() == Kind::KArrayType) {
		auto nestedArrayType = static_cast<const llvm::itanium_demangle::ArrayType *>(arrayTypeNode);
		dimensions.emplace_back(parseDimension(nestedArrayType->getDimension()));
		arrayTypeNode = nestedArrayType->getBase();
	}

	auto type = parseType(arrayTypeNode);

	return ctypes::ArrayType::create(context, type, dimensions);
}

unsigned ItaniumAstCtypesParser::parseDimension(const llvm::itanium_demangle::NodeOrString *dimensions)
{
	assert(dimensions && "Violated precondition.");

	std::string dimStr;
	if (dimensions->isString()) {
		dimStr = toString(dimensions->asString());
	} else {
		dimStr = toString(dimensions->asNode());
	}

	unsigned dim = 0;
	try {
		size_t lenParsed;
		int parsed = std::stoi(dimStr, &lenParsed);
		if (lenParsed == dimStr.length()) {
			dim = static_cast<unsigned>(parsed);
		}
	} catch (std::exception &e) {
		dim = 0;
	}
	return dim;
}

std::shared_ptr<ctypes::FunctionType> ItaniumAstCtypesParser::parseFuntionType(
	const llvm::itanium_demangle::FunctionType *typeNode)
{
	std::shared_ptr<ctypes::Type> returnType = parseType(typeNode->getReturnType());
	bool isVarArg = false;
	ctypes::FunctionType::Parameters parameters =
		parseFuncTypeParameters(typeNode->getParameters(), isVarArg);
	ctypes::Function::VarArgness varArgness = toVarArgness(isVarArg);
	ctypes::CallConvention callConvention = ctypes::CallConvention();    // TODO

	return ctypes::FunctionType::create(context, returnType, parameters, callConvention, varArgness);
}

ctypes::FunctionType::Parameters ItaniumAstCtypesParser::parseFuncTypeParameters(
	const llvm::itanium_demangle::NodeArray parameters_node,
	bool &isVarArg)
{
	using Parameters = ctypes::FunctionType::Parameters;

	Parameters parameters;

	for (size_t i = 0; i < parameters_node.size(); ++i) {
		auto type = parseType(parameters_node[i]);
		if (type->isNamed()
			&& std::static_pointer_cast<ctypes::NamedType>(type)->getName() == "...") {
			isVarArg = true;
		} else {
			parameters.emplace_back(type);
		}
	}

	return parameters;
}

}
}
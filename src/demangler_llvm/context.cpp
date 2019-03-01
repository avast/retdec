#include <retdec/utils/container.h>

#include "llvm/Demangle/context.h"
#include "llvm/Demangle/borland_ast_types.h"

namespace retdec {
namespace demangler {
namespace borland {

std::shared_ptr<BuiltInTypeNode> Context::getBuiltInType(const StringView &name, const Qualifiers &quals) const
{
	std::string name_str = std::string{name.begin(), name.size()};
	bool isVolatile = quals.isVolatile();
	bool isConst = quals.isConst();

	auto key = std::make_tuple(name_str, isVolatile, isConst);
	return retdec::utils::mapGetValueOrDefault(builtInTypes, key);
}

void Context::addBuiltInType(const std::shared_ptr<BuiltInTypeNode> &type)
{
	assert(type && "violated precondition - type cannot be null");

	auto name = type->typeName();
	std::string name_str = std::string{name.begin(), name.size()};
	bool isVolatile = type->quals().isVolatile();
	bool isConst = type->quals().isConst();

	auto key = std::make_tuple(name_str, isVolatile, isConst);

	builtInTypes.emplace(key, type);
}

std::shared_ptr<CharTypeNode> Context::getCharType(
	const ThreeStateSignness &signness,
	const Qualifiers &quals) const
{
	auto key = std::make_tuple(signness, quals.isVolatile(), quals.isConst());
	return retdec::utils::mapGetValueOrDefault(charTypes, key);
}

void Context::addCharType(const std::shared_ptr<CharTypeNode> &type)
{
	assert(type && "violated precondition - type cannot be null");

	auto signness = type->signness();
	auto key = std::make_tuple(signness, type->quals().isVolatile(), type->quals().isConst());

	charTypes.emplace(key, type);
}

std::shared_ptr<IntegralTypeNode> Context::getIntegralType(
	const StringView &name, bool isUnsigned, const Qualifiers &quals) const
{
	std::string name_str = std::string{name.begin(), name.size()};
	bool isVolatile = quals.isVolatile();
	bool isConst = quals.isConst();

	auto key = std::make_tuple(name_str, isUnsigned, isVolatile, isConst);
	return retdec::utils::mapGetValueOrDefault(integralTypes, key);
}

void Context::addIntegralType(const std::shared_ptr<IntegralTypeNode> &type)
{
	assert(type && "violated precondition - type cannot be null");

	auto name = type->typeName();
	std::string name_str = std::string{name.begin(), name.size()};
	bool isUnsigned = type->isUnsigned();
	bool isVolatile = type->quals().isVolatile();
	bool isConst = type->quals().isConst();

	auto key = std::make_tuple(name_str, isUnsigned, isVolatile, isConst);

	integralTypes.emplace(key, type);
}

std::shared_ptr<FloatTypeNode> Context::getFloatType(const StringView &name, const Qualifiers &quals) const
{
	std::string name_str = std::string{name.begin(), name.size()};
	bool isVolatile = quals.isVolatile();
	bool isConst = quals.isConst();

	auto key = std::make_tuple(name_str, isVolatile, isConst);
	return std::static_pointer_cast<FloatTypeNode>(retdec::utils::mapGetValueOrDefault(builtInTypes, key));
}

void Context::addFloatType(const std::shared_ptr<FloatTypeNode> &type)
{
	assert(type && "violated precondition - type cannot be null");

	auto name = type->typeName();
	std::string name_str = std::string{name.begin(), name.size()};
	bool isVolatile = type->quals().isVolatile();
	bool isConst = type->quals().isConst();

	auto key = std::make_tuple(name_str, isVolatile, isConst);

	builtInTypes.emplace(key, type);
}

std::shared_ptr<PointerTypeNode> Context::getPointerType(
	std::shared_ptr<Node> pointee, const Qualifiers &quals) const
{
	auto key = std::make_tuple(pointee, quals.isVolatile(), quals.isConst());
	return retdec::utils::mapGetValueOrDefault(pointerTypes, key);
}

void Context::addPointerType(const std::shared_ptr<PointerTypeNode> &type)
{
	assert(type && "violated precondition - type cannot be null");

	auto pointee = type->pointee();
	auto isVolatile = type->quals().isVolatile();
	auto isConst = type->quals().isConst();
	auto key = std::make_tuple(pointee, isVolatile, isConst);

	pointerTypes.emplace(key, type);
}

std::shared_ptr<ReferenceTypeNode> Context::getReferenceType(std::shared_ptr<Node> pointee) const
{
	return retdec::utils::mapGetValueOrDefault(referenceTypes, pointee);
}

void Context::addReferenceType(const std::shared_ptr<ReferenceTypeNode> &type)
{
	assert(type && "violated precondition - type cannot be null");

	referenceTypes.emplace(type->pointee(), type);
}

std::shared_ptr<NamedTypeNode> Context::getNamedType(const StringView &name, const Qualifiers &quals) const
{
	std::string name_str = std::string{name.begin(), name.size()};
	bool isVolatile = quals.isVolatile();
	bool isConst = quals.isConst();

	auto key = std::make_tuple(name_str, isVolatile, isConst);
	return retdec::utils::mapGetValueOrDefault(namedTypes, key);
}

void Context::addNamedType(const std::shared_ptr<retdec::demangler::borland::NamedTypeNode> &type)
{
	assert(type && "violated precondition - type cannot be null");

	auto name = type->typeName();
	std::string name_str = std::string{name.begin(), name.size()};
	bool isVolatile = type->quals().isVolatile();
	bool isConst = type->quals().isConst();

	auto key = std::make_tuple(name_str, isVolatile, isConst);

	namedTypes.emplace(key, type);
}

std::shared_ptr<Node> Context::getFunction(const retdec::demangler::borland::StringView &mangled) const
{
	auto key = std::string{mangled.begin(), mangled.size()};
	return retdec::utils::mapGetValueOrDefault(functions, key);
}

void Context::addFunction(
	const retdec::demangler::borland::StringView &mangled,
	const std::shared_ptr<retdec::demangler::borland::Node> &function)
{
	assert(function && "violated precondition - function cannot be null");

	auto key = std::string{mangled.begin(), mangled.size()};
	functions.emplace(key, function);
}

std::shared_ptr<NameNode> Context::getName(const retdec::demangler::borland::StringView &name) const
{
	auto key = std::string{name.begin(), name.size()};
	return retdec::utils::mapGetValueOrDefault(nameNodes, key);
}

void Context::addName(const std::shared_ptr<retdec::demangler::borland::NameNode> &name)
{
	assert(name && "violated precondition - function cannot be null");

	auto key = name->str();
	nameNodes.emplace(key, name);
}

std::shared_ptr<NestedNameNode> Context::getNestedName(
	std::shared_ptr<retdec::demangler::borland::Node> super,
	std::shared_ptr<retdec::demangler::borland::Node> name)
{
	auto key = std::make_tuple(super, name);
	return retdec::utils::mapGetValueOrDefault(nestedNameNodes, key);
}

void Context::addNestedName(const std::shared_ptr<retdec::demangler::borland::NestedNameNode> &name)
{
	assert(name && "violated precondition - function cannot be null");

	auto key = std::make_tuple(name->super(), name->name());
	nestedNameNodes.emplace(key, name);
}

}    // borland
}    // demangler
}    // retdec


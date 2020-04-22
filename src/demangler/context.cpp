/**
 * @file src/demangler/context.cpp
 * @brief Implementation of cacheing of nodes in borland demangler AST.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/container.h"
#include "retdec/demangler/context.h"
#include "retdec/demangler/borland_ast/borland_ast.h"

namespace retdec {
namespace demangler {
namespace borland {

std::shared_ptr<BuiltInTypeNode> Context::getBuiltInType(const std::string &name, const Qualifiers &quals) const
{
	bool isVolatile = quals.isVolatile();
	bool isConst = quals.isConst();

	auto key = std::make_tuple(name, isVolatile, isConst);

	return retdec::utils::mapGetValueOrDefault(builtInTypes, key);
}

void Context::addBuiltInType(const std::shared_ptr<BuiltInTypeNode> &type)
{
	assert(type && "violated precondition - type cannot be null");

	auto name = type->typeName();
	bool isVolatile = type->quals().isVolatile();
	bool isConst = type->quals().isConst();

	auto key = std::make_tuple(name, isVolatile, isConst);

	builtInTypes.emplace(key, type);
}

std::shared_ptr<CharTypeNode> Context::getCharType(
	const ThreeStateSignedness &signedness,
	const Qualifiers &quals) const
{
	bool isVolatile = quals.isVolatile();
	bool isConst = quals.isConst();

	auto key = std::make_tuple(signedness, isVolatile, isConst);

	return retdec::utils::mapGetValueOrDefault(charTypes, key);
}

void Context::addCharType(const std::shared_ptr<CharTypeNode> &type)
{
	assert(type && "violated precondition - type cannot be null");

	auto signedness = type->signedness();
	bool isVolatile = type->quals().isVolatile();
	bool isConst = type->quals().isConst();

	auto key = std::make_tuple(signedness, isVolatile, isConst);

	charTypes.emplace(key, type);
}

std::shared_ptr<IntegralTypeNode> Context::getIntegralType(
	const std::string &name, bool isUnsigned, const Qualifiers &quals) const
{
	bool isVolatile = quals.isVolatile();
	bool isConst = quals.isConst();

	auto key = std::make_tuple(name, isUnsigned, isVolatile, isConst);

	return retdec::utils::mapGetValueOrDefault(integralTypes, key);
}

void Context::addIntegralType(const std::shared_ptr<IntegralTypeNode> &type)
{
	assert(type && "violated precondition - type cannot be null");

	auto name = type->typeName();
	bool isUnsigned = type->isUnsigned();
	bool isVolatile = type->quals().isVolatile();
	bool isConst = type->quals().isConst();

	auto key = std::make_tuple(name, isUnsigned, isVolatile, isConst);

	integralTypes.emplace(key, type);
}

std::shared_ptr<FloatTypeNode> Context::getFloatType(const std::string &name, const Qualifiers &quals) const
{
	bool isVolatile = quals.isVolatile();
	bool isConst = quals.isConst();

	auto key = std::make_tuple(name, isVolatile, isConst);

	return std::static_pointer_cast<FloatTypeNode>(retdec::utils::mapGetValueOrDefault(builtInTypes, key));
}

void Context::addFloatType(const std::shared_ptr<FloatTypeNode> &type)
{
	assert(type && "violated precondition - type cannot be null");

	auto name = type->typeName();
	bool isVolatile = type->quals().isVolatile();
	bool isConst = type->quals().isConst();

	auto key = std::make_tuple(name, isVolatile, isConst);

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

std::shared_ptr<RReferenceTypeNode> Context::getRReferenceType(std::shared_ptr<Node> pointee) const
{
	return retdec::utils::mapGetValueOrDefault(rReferenceTypes, pointee);
}

void Context::addRReferenceType(const std::shared_ptr<RReferenceTypeNode> &type)
{
	assert(type && "violated precondition - type cannot be null");

	rReferenceTypes.emplace(type->pointee(), type);
}

std::shared_ptr<NamedTypeNode> Context::getNamedType(const std::string &name, const Qualifiers &quals) const
{
	bool isVolatile = quals.isVolatile();
	bool isConst = quals.isConst();

	auto key = std::make_tuple(name, isVolatile, isConst);

	return retdec::utils::mapGetValueOrDefault(namedTypes, key);
}

void Context::addNamedType(
	const std::string &mangled,
	const Qualifiers &quals,
	const std::shared_ptr<NamedTypeNode> &type)
{
	assert(type && "violated precondition - type cannot be null");

	bool isVolatile = type->quals().isVolatile();
	bool isConst = type->quals().isConst();

	auto key = std::make_tuple(mangled, isVolatile, isConst);

	namedTypes.emplace(key, type);
}

std::shared_ptr<Node> Context::getFunction(const std::string &mangled) const
{
	return retdec::utils::mapGetValueOrDefault(functions, mangled);
}

void Context::addFunction(
	const std::string &mangled,
	const std::shared_ptr<Node> &function)
{
	assert(function && "violated precondition - function cannot be null");

	functions.emplace(mangled, function);
}

std::shared_ptr<NameNode> Context::getName(const std::string &name) const
{
	return retdec::utils::mapGetValueOrDefault(nameNodes, name);
}

void Context::addName(const std::shared_ptr<NameNode> &name)
{
	assert(name && "violated precondition - function cannot be null");

	auto key = name->str();
	nameNodes.emplace(key, name);
}

std::shared_ptr<NestedNameNode> Context::getNestedName(
	std::shared_ptr<Node> super,
	std::shared_ptr<Node> name)
{
	auto key = std::make_tuple(super, name);
	return retdec::utils::mapGetValueOrDefault(nestedNameNodes, key);
}

void Context::addNestedName(const std::shared_ptr<NestedNameNode> &name)
{
	assert(name && "violated precondition - function cannot be null");

	auto key = std::make_tuple(name->super(), name->name());
	nestedNameNodes.emplace(key, name);
}

std::shared_ptr<ArrayNode> Context::getArray(
	std::shared_ptr<Node> pointee,
	unsigned size,
	const Qualifiers &quals)
{
	auto key = std::make_tuple(pointee, size, quals.isVolatile(), quals.isConst());
	return retdec::utils::mapGetValueOrDefault(arrayNodes, key);
}

void Context::addArrayType(const std::shared_ptr<ArrayNode> &array) {
	assert(array && "violated precondition - array cannot be null");

	auto pointee = array->pointee();
	auto size = array->size();
	auto isVolatile = array->quals().isVolatile();
	auto isConst = array->quals().isConst();

	auto key = std::make_tuple(pointee, size, isVolatile, isConst);

	arrayNodes.emplace(key, array);
}

}    // borland
}    // demangler
}    // retdec

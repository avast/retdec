//
// Created by adam on 14.2.19.
//

#include <sstream>
#include <map>

#include "llvm/Demangle/borland_ast.h"
#include "llvm/Demangle/borland_ast_types.h"
#include "llvm/Demangle/context.h"

namespace retdec {
namespace demangler {
namespace borland {

TypeNode::TypeNode(const StringView &typeName, bool isVolatile, bool isConst) :
	Node(Kind::KTypeNode), _typeName(typeName), _isVolatile(isVolatile), _isConst(isConst) {}

bool TypeNode::isVolatile() const
{
	return _isVolatile;
}

bool TypeNode::isConst() const
{
	return _isConst;
}

StringView TypeNode::typeName() const
{
	return _typeName;
}

void TypeNode::printLeft(std::ostream &s) const
{
	if (_isVolatile) {
		s << "volatile ";
	}
	if (_isConst) {
		s << "const ";
	}
	s << std::string{_typeName.begin(), _typeName.size()};
}

/**
 * @brief Private constructor for built-in type nodes. Use create().
 * @param typeName Representation of type name.
 */
BuiltInTypeNode::BuiltInTypeNode(const StringView &typeName, bool isVolatile, bool isConst) :
	TypeNode(typeName, isVolatile, isConst)
{
	_kind = Kind::KBuiltInType;
}

/**
 * @brief Creates unique pointer to built-in type nodes.
 * @param typeName Representation of type name.
 * @return Unique pointer to built-in type nodes.
 */
std::shared_ptr<BuiltInTypeNode> BuiltInTypeNode::create(
	Context &context,
	const StringView &typeName,
	bool isVolatile,
	bool isConst)
{
	auto type = context.getBuiltInType(typeName, isVolatile, isConst);
	if (type && type->kind() == Kind::KBuiltInType) {
		return type;
	}

	auto newType = std::shared_ptr<BuiltInTypeNode>(new BuiltInTypeNode(typeName, isVolatile, isConst));
	context.addBuiltInType(newType);
	return newType;
}

CharTypeNode::CharTypeNode(ThreeStateSignness signness, bool isVolatile, bool isConst) :
	BuiltInTypeNode("char", isVolatile, isConst), _signness(signness)
{
	_kind = Kind::KCharType;
}

std::shared_ptr<CharTypeNode> CharTypeNode::create(
	Context &context,
	ThreeStateSignness signness,
	bool isVolatile,
	bool isConst)
{
	auto type = context.getCharType(signness, isVolatile, isConst);
	if (type && type->kind() == Kind::KCharType) {
		return type;
	}

	auto newType = std::shared_ptr<CharTypeNode>(new CharTypeNode(signness, isVolatile, isConst));
	context.addCharType(newType);
	return newType;
}

ThreeStateSignness CharTypeNode::signness()
{
	return _signness;
}

void CharTypeNode::printLeft(std::ostream &s) const
{
	if (_isVolatile) {
		s << "volatile ";
	}
	if (_isConst) {
		s << "const ";
	}
	switch (_signness) {
	case ThreeStateSignness::signed_char: s << "signed char";
		break;
	case ThreeStateSignness::unsigned_char: s << "unsigned char";
		break;
	default: s << "char";
	}
}

IntegralTypeNode::IntegralTypeNode(
	const StringView &typeName, bool isUnsigned, bool isVolatile, bool isConst) :
	BuiltInTypeNode(typeName, isVolatile, isConst), _isUnsigned(isUnsigned)
{
	_kind = Kind::KIntegralType;
};

std::shared_ptr<IntegralTypeNode> IntegralTypeNode::create(
	Context &context,
	const StringView &typeName,
	bool isUnsigned,
	bool isVolatile,
	bool isConst)
{
	auto type = context.getIntegralType(typeName, isUnsigned, isVolatile, isConst);
	if (type && type->kind() == Kind::KIntegralType) {
		return type;
	}

	auto newType = std::shared_ptr<IntegralTypeNode>(new IntegralTypeNode(typeName, isUnsigned, isVolatile, isConst));
	context.addIntegralType(newType);
	return newType;
}

bool IntegralTypeNode::isUnsigned()
{
	return _isUnsigned;
}

void IntegralTypeNode::printLeft(std::ostream &s) const
{
	if (_isVolatile) {
		s << "volatile ";
	}
	if (_isConst) {
		s << "const ";
	}
	if (_isUnsigned) {
		s << "unsigned ";
	}
	s << std::string{_typeName.begin(), _typeName.size()};
}

FloatTypeNode::FloatTypeNode(const StringView &typeName, bool isVolatile, bool isConst) :
	BuiltInTypeNode(typeName, isVolatile, isConst)
{
	_kind = Kind::KFloatType;
}

std::shared_ptr<FloatTypeNode> FloatTypeNode::create(
	Context &context,
	const StringView &typeName,
	bool isVolatile,
	bool isConst)
{
	auto type = context.getFloatType(typeName, isVolatile, isConst);
	if (type && type->kind() == Kind::KFloatType) {
		return type;
	}

	auto newType = std::shared_ptr<FloatTypeNode>(new FloatTypeNode(typeName, isVolatile, isConst));
	context.addFloatType(newType);
	return newType;
}

NamedTypeNode::NamedTypeNode(std::shared_ptr<Node> typeName, bool isVolatile, bool isConst) :
	TypeNode("", isVolatile, isConst), _typeName(typeName)
{
	_kind = Kind::KNamedType;
}

std::shared_ptr<NamedTypeNode> NamedTypeNode::create(
	retdec::demangler::borland::Context &context,
	std::shared_ptr<Node> typeName,
	bool isVolatile,
	bool isConst)
{
	// TODO context
//	auto type = context.getNamedType(typeName, isVolatile, isConst);
//	if (type && type->kind() == Kind::KNamedType) {
//		return type;
//	}
//
	auto newType = std::shared_ptr<NamedTypeNode>(new NamedTypeNode(typeName, isVolatile, isConst));
//	context.addNamedType(newType);
	return newType;
}

std::shared_ptr<Node> NamedTypeNode::name()
{
	return _typeName;
}

void NamedTypeNode::printLeft(std::ostream &s) const
{
	if (_isVolatile) {
		s << "volatile ";
	}
	if (_isConst) {
		s << "const ";
	}

	s << _typeName->str();
}

PointerTypeNode::PointerTypeNode(std::shared_ptr<Node> pointee, bool isVolatile, bool isConst) :
	TypeNode("", isVolatile, isConst), _pointee(std::move(pointee))
{    // TODO clang hovori ze tam ma byt move tak to over
	_kind = Kind::KPointerType;
}

std::shared_ptr<PointerTypeNode> PointerTypeNode::create(
	Context context,
	std::shared_ptr<Node> pointee,
	bool isVolatile,
	bool isConst)
{
	auto type = context.getPointerType(pointee, isVolatile, isConst);
	if (type && type->kind() == Kind::KPointerType) {
		return type;
	}

	auto newType = std::shared_ptr<PointerTypeNode>(new PointerTypeNode(pointee, isVolatile, isConst));
	context.addPointerType(newType);
	return newType;
}

std::shared_ptr<Node> PointerTypeNode::pointee()
{
	return _pointee;
}

void PointerTypeNode::printLeft(std::ostream &s) const
{
	if (_pointee->hasRight()) {
		_pointee->printLeft(s);
		s << " (*";
		if (_isVolatile) {
			s << " volatile";
		}
		if (_isConst) {
			s << " const";
		}
		s << ")";
		_pointee->printRight(s);
	} else {
		_pointee->print(s);
		s << " *";
		if (_isVolatile) {
			s << " volatile";
		}
		if (_isConst) {
			s << " const";
		}
	}
}

ReferenceTypeNode::ReferenceTypeNode(std::shared_ptr<Node> pointee) :
	TypeNode("", false, false), _pointee(pointee)
{
	_kind = Kind::KReferenceType;
}

std::shared_ptr<ReferenceTypeNode> ReferenceTypeNode::create(
	retdec::demangler::borland::Context &context,
	std::shared_ptr<retdec::demangler::borland::Node> pointee)
{
	auto type = context.getReferenceType(pointee);
	if (type && type->kind() == Kind::KReferenceType) {
		return type;
	}

	auto newType = std::shared_ptr<ReferenceTypeNode>(new ReferenceTypeNode(pointee));
	context.addReferenceType(newType);
	return newType;
}

std::shared_ptr<Node> ReferenceTypeNode::pointee()
{
	return _pointee;
}

void ReferenceTypeNode::printLeft(std::ostream &s) const
{
	if (_pointee->hasRight()) {
		_pointee->printLeft(s);
		s << " (&)";
		_pointee->printRight(s);
	} else {
		_pointee->print(s);
		s << " &";
	}
}

RReferenceTypeNode::RReferenceTypeNode(std::shared_ptr<Node> pointee) :
	TypeNode("", false, false), _pointee(pointee)
{
	_kind = Kind::KRReferenceType;
}

std::shared_ptr<RReferenceTypeNode> RReferenceTypeNode::create(
	Context &context, std::shared_ptr<Node> pointee)
{
	return std::shared_ptr<RReferenceTypeNode>(new RReferenceTypeNode(pointee));
}

std::shared_ptr<Node> RReferenceTypeNode::pointee()
{
	return _pointee;
}

void RReferenceTypeNode::printLeft(std::ostream &s) const
{
	if (_pointee->hasRight()) {
		_pointee->printLeft(s);
		s << " (&&)";
		_pointee->printRight(s);
	} else {
		_pointee->print(s);
		s << " &&";
	}
}

ArrayNode::ArrayNode(
	std::shared_ptr<retdec::demangler::borland::Node> pointee,
	unsigned size,
	bool isVolatile,
	bool isConst) :
	TypeNode("", isVolatile, isConst), _pointee(pointee), _size(size)
{
	_kind = Kind::KArrayNode;
	_has_right = true;
}

std::shared_ptr<ArrayNode> ArrayNode::create(
	Context &context,
	std::shared_ptr<retdec::demangler::borland::Node> pointee,
	unsigned size,
	bool isVolatile,
	bool isConst)
{
	return std::shared_ptr<ArrayNode>(new ArrayNode(pointee, size, isVolatile, isConst));
}

void ArrayNode::printLeft(std::ostream &s) const
{
	_pointee->printLeft(s);
	if (isVolatile()) {
		s << " volatile";
	}
	if (isConst()) {
		s << " const";
	}
}

void ArrayNode::printRight(std::ostream &s) const
{
	s << "[" << _size << "]";
	_pointee->printRight(s);
}

}    // borland
}    // demangler
}    // retdec

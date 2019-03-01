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

TypeNode::TypeNode(const Qualifiers &quals) :
	Node(Kind::KTypeNode), _quals(quals) {}

Qualifiers TypeNode::quals()
{
	return _quals;
}

/**
 * @brief Private constructor for built-in type nodes. Use create().
 * @param typeName Representation of type name.
 */
BuiltInTypeNode::BuiltInTypeNode(const std::string &typeName, const Qualifiers &quals) :
	TypeNode(quals), _typeName(typeName)
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
	const std::string &typeName,
	const Qualifiers &quals)
{
	auto type = context.getBuiltInType(typeName, quals);
	if (type && type->kind() == Kind::KBuiltInType) {
		return type;
	}

	auto newType = std::shared_ptr<BuiltInTypeNode>(new BuiltInTypeNode(typeName, quals));
	context.addBuiltInType(newType);
	return newType;
}

std::string BuiltInTypeNode::typeName() const
{
	return _typeName;
}

void BuiltInTypeNode::printLeft(std::ostream &s) const
{
	_quals.printSpaceR(s);
	s << _typeName;
}

CharTypeNode::CharTypeNode(ThreeStateSignness signness, const Qualifiers &quals) :
	BuiltInTypeNode("char", quals), _signness(signness)
{
	_kind = Kind::KCharType;
}

std::shared_ptr<CharTypeNode> CharTypeNode::create(
	Context &context,
	ThreeStateSignness signness,
	const Qualifiers &quals)
{
	auto type = context.getCharType(signness, quals);
	if (type && type->kind() == Kind::KCharType) {
		return type;
	}

	auto newType = std::shared_ptr<CharTypeNode>(new CharTypeNode(signness, quals));
	context.addCharType(newType);
	return newType;
}

ThreeStateSignness CharTypeNode::signness()
{
	return _signness;
}

void CharTypeNode::printLeft(std::ostream &s) const
{
	_quals.printSpaceR(s);
	switch (_signness) {
	case ThreeStateSignness::signed_char: s << "signed char";
		break;
	case ThreeStateSignness::unsigned_char: s << "unsigned char";
		break;
	default: s << "char";
	}
}

IntegralTypeNode::IntegralTypeNode(
	const std::string &typeName, bool isUnsigned, const Qualifiers &quals) :
	BuiltInTypeNode(typeName, quals), _isUnsigned(isUnsigned)
{
	_kind = Kind::KIntegralType;
};

std::shared_ptr<IntegralTypeNode> IntegralTypeNode::create(
	Context &context,
	const std::string &typeName,
	bool isUnsigned,
	const Qualifiers &quals)
{
	auto type = context.getIntegralType(typeName, isUnsigned, quals);
	if (type && type->kind() == Kind::KIntegralType) {
		return type;
	}

	auto newType = std::shared_ptr<IntegralTypeNode>(new IntegralTypeNode(typeName, isUnsigned, quals));
	context.addIntegralType(newType);
	return newType;
}

bool IntegralTypeNode::isUnsigned()
{
	return _isUnsigned;
}

void IntegralTypeNode::printLeft(std::ostream &s) const
{
	_quals.printSpaceR(s);
	if (_isUnsigned) {
		s << "unsigned ";
	}
	s << _typeName;
}

FloatTypeNode::FloatTypeNode(const std::string &typeName, const Qualifiers &quals) :
	BuiltInTypeNode(typeName, quals)
{
	_kind = Kind::KFloatType;
}

std::shared_ptr<FloatTypeNode> FloatTypeNode::create(
	Context &context,
	const std::string &typeName,
	const Qualifiers &quals)
{
	auto type = context.getFloatType(typeName, quals);
	if (type && type->kind() == Kind::KFloatType) {
		return type;
	}

	auto newType = std::shared_ptr<FloatTypeNode>(new FloatTypeNode(typeName, quals));
	context.addFloatType(newType);
	return newType;
}

NamedTypeNode::NamedTypeNode(std::shared_ptr<Node> typeName, const Qualifiers &quals) :
	TypeNode(quals), _typeName(typeName)
{
	_kind = Kind::KNamedType;
}

std::shared_ptr<NamedTypeNode> NamedTypeNode::create(
	retdec::demangler::borland::Context &context,
	std::shared_ptr<Node> typeName,
	const Qualifiers &quals)
{
	return std::shared_ptr<NamedTypeNode>(new NamedTypeNode(typeName, quals));
}

std::shared_ptr<Node> NamedTypeNode::name()
{
	return _typeName;
}

void NamedTypeNode::printLeft(std::ostream &s) const
{
	_quals.printSpaceR(s);
	s << _typeName->str();
}

PointerTypeNode::PointerTypeNode(const std::shared_ptr<Node> &pointee, const Qualifiers &quals) :
	TypeNode(quals), _pointee(std::move(pointee))
{
	_kind = Kind::KPointerType;
	_has_right = _pointee->hasRight();
}

std::shared_ptr<PointerTypeNode> PointerTypeNode::create(
	Context &context,
	const std::shared_ptr<Node> &pointee,
	const Qualifiers &quals)
{
	auto type = context.getPointerType(pointee, quals);
	if (type && type->kind() == Kind::KPointerType) {
		return type;
	}

	auto newType = std::shared_ptr<PointerTypeNode>(new PointerTypeNode(pointee, quals));
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
		s << "(*";
		_quals.printSpaceL(s);
	} else {
		_pointee->print(s);
		s << " *";
		_quals.printSpaceL(s);
	}
}

void PointerTypeNode::printRight(std::ostream &s) const
{
	s << ")";
	_pointee->printRight(s);
}

ReferenceTypeNode::ReferenceTypeNode(std::shared_ptr<Node> pointee) :
	TypeNode({false, false}), _pointee(std::move(pointee))
{
	_kind = Kind::KReferenceType;
	_has_right = _pointee->hasRight();
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
		s << "(&";
	} else {
		_pointee->print(s);
		s << " &";
		_quals.printSpaceL(s);
	}
}

void ReferenceTypeNode::printRight(std::ostream &s) const
{
	s << ")";
	_pointee->printRight(s);
}

RReferenceTypeNode::RReferenceTypeNode(std::shared_ptr<Node> pointee) :
	TypeNode({false, false}), _pointee(std::move(pointee))
{
	_kind = Kind::KRReferenceType;
	_has_right = _pointee->hasRight();
}

std::shared_ptr<RReferenceTypeNode> RReferenceTypeNode::create(
	Context &context, std::shared_ptr<Node> pointee)
{
	return std::shared_ptr<RReferenceTypeNode>(new RReferenceTypeNode(std::move(pointee)));
}

std::shared_ptr<Node> RReferenceTypeNode::pointee()
{
	return _pointee;
}

void RReferenceTypeNode::printLeft(std::ostream &s) const
{
	if (_pointee->hasRight()) {
		_pointee->printLeft(s);
		s << "(&&";
	} else {
		_pointee->print(s);
		s << " &&";
		_quals.printSpaceL(s);
	}
}

void RReferenceTypeNode::printRight(std::ostream &s) const
{
	s << ")";
	_pointee->printRight(s);
}

ArrayNode::ArrayNode(
	std::shared_ptr<retdec::demangler::borland::Node> pointee,
	unsigned size,
	const Qualifiers &quals) :
	TypeNode(quals), _pointee(std::move(pointee)), _size(size)
{
	_kind = Kind::KArrayNode;
	_has_right = true;
}

std::shared_ptr<ArrayNode> ArrayNode::create(
	Context &context,
	std::shared_ptr<retdec::demangler::borland::Node> pointee,
	unsigned size,
	const Qualifiers &quals)
{
	return std::shared_ptr<ArrayNode>(new ArrayNode(pointee, size, quals));
}

void ArrayNode::printLeft(std::ostream &s) const
{
	_pointee->printLeft(s);
	_quals.printSpaceL(s);
}

void ArrayNode::printRight(std::ostream &s) const
{
	s << "[" << _size << "]";
	_pointee->printRight(s);
}

FunctionTypeNode::FunctionTypeNode(
	retdec::demangler::borland::CallConv callConv,
	std::shared_ptr<retdec::demangler::borland::Node> params,
	std::shared_ptr<retdec::demangler::borland::Node> retType,
	retdec::demangler::borland::Qualifiers &quals,
	bool isVarArg) :
	TypeNode(quals), _callConv(callConv), _params(params), _retType(retType), _isVarArg(isVarArg)
{
	_kind = Kind::KFunctionType;
	_has_right = true;
}

std::shared_ptr<FunctionTypeNode> FunctionTypeNode::create(
	retdec::demangler::borland::Context &context,
	retdec::demangler::borland::CallConv callConv,
	std::shared_ptr<retdec::demangler::borland::Node> params,
	std::shared_ptr<retdec::demangler::borland::Node> retType,
	retdec::demangler::borland::Qualifiers &quals,
	bool isVarArg)
{
	return std::shared_ptr<FunctionTypeNode>(new FunctionTypeNode(callConv, params, retType, quals, isVarArg));
}

void FunctionTypeNode::printLeft(std::ostream &s) const
{
	if (_retType) {
		if (_retType->hasRight()) {
			_retType->printLeft(s);
		} else {
			_retType->print(s);
			s << " ";
		}
	}

	switch (_callConv) {
	case CallConv::fastcall: s << "__fastcall ";
		break;
	case CallConv::stdcall: s << "__stdcall ";
		break;
	default: break;
	}
}

void FunctionTypeNode::printRight(std::ostream &s) const
{
	s << "(";
	if (_params) {
		_params->print(s);
	}
	if (_isVarArg) {
		s << ", ...";
	}
	s << ")";

	if (_retType && _retType->hasRight()) {
		_retType->printRight(s);
	}

	_quals.printSpaceL(s);
}

}    // borland
}    // demangler
}    // retdec

/**
 * @file src/demangler_llvm/borland_ast_types.cpp
 * @brief Implementation of types in demangler ast.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <sstream>
#include <map>

#include "llvm/Demangle/borland_ast.h"
#include "llvm/Demangle/borland_ast_types.h"
#include "llvm/Demangle/context.h"

namespace retdec {
namespace demangler {
namespace borland {

/**
 * Constructor for abstract class TypeNode.
 * @param quals Qualifiers object. Types can have const/volatile qualifiers.
 */
TypeNode::TypeNode(const Qualifiers &quals) :
	Node(Kind::KTypeNode), _quals(quals) {}

/**
 * @return Type qualifiers.
 */
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

/**
 * @return String representation of type name.
 */
std::string BuiltInTypeNode::typeName() const
{
	return _typeName;
}

/**
 * @brief Prints text representation of type with qualifiers to output stream.
 */
void BuiltInTypeNode::printLeft(std::ostream &s) const
{
	_quals.printSpaceR(s);
	s << _typeName;
}

/**
 * @brief Private constructor for Char types. Use create().
 */
CharTypeNode::CharTypeNode(ThreeStateSignedness signedness, const Qualifiers &quals) :
	BuiltInTypeNode("char", quals), _signedness(signedness)
{
	_kind = Kind::KCharType;
}

/**
 * @brief Function for creating char types.
 * If type the same type was already created, then that instance is returned.
 * @param context Storage for types.
 * @param signedness Char signednes. Chars can be char, signed char, unsigned char. All are distinct types by standard.
 * @param quals See BuiltInTypeNode quals.
 * @return Node representing char type.
 */
std::shared_ptr<CharTypeNode> CharTypeNode::create(
	Context &context,
	ThreeStateSignedness signedness,
	const Qualifiers &quals)
{
	auto type = context.getCharType(signedness, quals);
	if (type && type->kind() == Kind::KCharType) {
		return type;
	}

	auto newType = std::shared_ptr<CharTypeNode>(new CharTypeNode(signedness, quals));
	context.addCharType(newType);
	return newType;
}

/**
 * @return signedness of type.
 */
ThreeStateSignedness CharTypeNode::signedness()
{
	return _signedness;
}

/**
 * @brief Prints text representation of char type with qualifiers to output stream.
 */
void CharTypeNode::printLeft(std::ostream &s) const
{
	_quals.printSpaceR(s);
	switch (_signedness) {
	case ThreeStateSignedness::signed_char:
		s << "signed char";
		break;
	case ThreeStateSignedness::unsigned_char:
		s << "unsigned char";
		break;
	default:
		s << "char";
	}
}

/**
 * @brief Private constructor for integral types. Use create().
 */
IntegralTypeNode::IntegralTypeNode(
	const std::string &typeName, bool isUnsigned, const Qualifiers &quals) :
	BuiltInTypeNode(typeName, quals), _isUnsigned(isUnsigned)
{
	_kind = Kind::KIntegralType;
};

/**
 * @brief Function for creating integral types.
 * If type the same type was already created, then that instance is returned.
 * @param context Storage for types.
 * @param typeName Name of integral type to create.
 * @param isUnsigned Information about intgral type signedness.
 * @param quals See BuiltInTypeNode quals.
 * @return Node representing integral type.
 */
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

/**
 * @return true if type is unsigned, else false.
 */
bool IntegralTypeNode::isUnsigned()
{
	return _isUnsigned;
}

/**
 * @brief Prints text representation of type with qualifiers to output stream.
 */
void IntegralTypeNode::printLeft(std::ostream &s) const
{
	_quals.printSpaceR(s);
	if (_isUnsigned) {
		s << "unsigned ";
	}
	s << _typeName;
}

/**
 * @brief Private constructor for floating point types. Use create().
 */
FloatTypeNode::FloatTypeNode(const std::string &typeName, const Qualifiers &quals) :
	BuiltInTypeNode(typeName, quals)
{
	_kind = Kind::KFloatType;
}

/**
 * @brief Function for creating floating point types.
 * If type the same type was already created, then that instance is returned.
 * @param context Storage for types.
 * @param typeName Name of integral type to create.
 * @param quals See BuiltInTypeNode quals.
 * @return Node representing floating point type.
 */
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

/**
 * Private constructor for named types. Use create().
 */
NamedTypeNode::NamedTypeNode(std::shared_ptr<Node> typeName, const Qualifiers &quals) :
	TypeNode(quals), _typeName(typeName)
{
	_kind = Kind::KNamedType;
}

/**
 * @brief Function for creating named types.
 * If type the same type was already created, then that instance is returned.
 * @param context Storage for types.
 * @param typeName Name of integral type to create.
 * @param quals See BuiltInTypeNode quals.
 * @return Node representing named type.
 */
std::shared_ptr<NamedTypeNode> NamedTypeNode::create(
	std::shared_ptr<Node> typeName,
	const Qualifiers &quals)
{
	return std::shared_ptr<NamedTypeNode>(new NamedTypeNode(std::move(typeName), quals));
}

/**
 * @return Node representing name.
 */
std::shared_ptr<Node> NamedTypeNode::name()
{
	return _typeName;
}

/**
 * @brief Prints text representation of named type with qualifiers to output stream.
 */
void NamedTypeNode::printLeft(std::ostream &s) const
{
	_quals.printSpaceR(s);
	s << _typeName->str();
}

/**
 * Private constructor for pointers. Use create().
 */
PointerTypeNode::PointerTypeNode(const std::shared_ptr<Node> &pointee, const Qualifiers &quals) :
	TypeNode(quals), _pointee(std::move(pointee))
{
	_kind = Kind::KPointerType;
	_has_right = _pointee->hasRight();
}

/**
 * @brief Function for creating pointers.
 * If type the same type was already created, then that instance is returned.
 * @param context Storage for types.
 * @param pointee Pointed type.
 * @param quals See BuiltInTypeNode quals.
 * @return Node representing pointer type.
 */
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

/**
 * @return Pointed type.
 */
std::shared_ptr<Node> PointerTypeNode::pointee()
{
	return _pointee;
}

/**
 * @brief Prints left side of pointer type or whole, depending on pointee.
 * Right side printing is used for arrays and pointers to function types.
 */
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

/**
 * @brief Prints right side of pointer type.
 * Used for array and funtion types.
 */
void PointerTypeNode::printRight(std::ostream &s) const
{
	s << ")";
	_pointee->printRight(s);
}

/**
 * Private constructor for references. Use create().
 * Reference can't be const or volatile.
 */
ReferenceTypeNode::ReferenceTypeNode(std::shared_ptr<Node> pointee) :
	TypeNode({false, false}), _pointee(std::move(pointee))
{
	_kind = Kind::KReferenceType;
	_has_right = _pointee->hasRight();
}

/**
 * @brief Function for creating references.
 * If type the same type was already created, then that instance is returned.
 * @param context Storage for types.
 * @param pointee Referenced type.
 * @return Node representing reference type.
 */
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

/**
 * @return Referenced type.
 */
std::shared_ptr<Node> ReferenceTypeNode::pointee()
{
	return _pointee;
}

/**
 * @brief Prints left side of reference type or whole, depending on pointee.
 * Right side printing is used for arrays and references to function types.
 */
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

/**
 * @brief Prints right side of reference type.
 * Used for array and funtion types.
 */
void ReferenceTypeNode::printRight(std::ostream &s) const
{
	s << ")";
	_pointee->printRight(s);
}

/**
 * Private constructor for r-value references. Use create().
 * Reference can't be const or volatile.
 */
RReferenceTypeNode::RReferenceTypeNode(std::shared_ptr<Node> pointee) :
	TypeNode({false, false}), _pointee(std::move(pointee))
{
	_kind = Kind::KRReferenceType;
	_has_right = _pointee->hasRight();
}

/**
 * @brief Function for creating r-value references.
 * If type the same type was already created, then that instance is returned.
 * @param context Storage for types.
 * @param pointee Referenced type.
 * @return Node representing r-value reference type.
 */
std::shared_ptr<RReferenceTypeNode> RReferenceTypeNode::create(
	Context &context, std::shared_ptr<Node> pointee)
{
//	return std::shared_ptr<RReferenceTypeNode>(new RReferenceTypeNode(std::move(pointee)));
	auto type = context.getRReferenceType(pointee);
	if (type) {
		return type;
	}

	auto newType = std::shared_ptr<RReferenceTypeNode>(new RReferenceTypeNode(pointee));
	context.addRReferenceType(newType);
	return newType;
}

/**
 * @return Referenced type.
 */
std::shared_ptr<Node> RReferenceTypeNode::pointee()
{
	return _pointee;
}

/**
 * @brief Prints left side of reference type or whole, depending on pointee.
 * Right side printing is used for arrays and references to function types.
 */
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

/**
 * @brief Prints right side of reference type.
 * Used for array and funtion types.
 */
void RReferenceTypeNode::printRight(std::ostream &s) const
{
	s << ")";
	_pointee->printRight(s);
}

/**
 * Private constructor for array types. Use create().
 */
ArrayNode::ArrayNode(
	std::shared_ptr<retdec::demangler::borland::Node> pointee,
	unsigned size,
	const Qualifiers &quals) :
	TypeNode(quals), _pointee(std::move(pointee)), _size(size)
{
	_kind = Kind::KArrayNode;
	_has_right = true;
}

/**
 * @brief Function for creating array types.
 * If type the same type was already created, then that instance is returned.
 * @param context Storage for types.
 * @param pointee Type of array.
 * @return Node representing array type.
 */
std::shared_ptr<ArrayNode> ArrayNode::create(
	Context &context,
	std::shared_ptr<retdec::demangler::borland::Node> pointee,
	unsigned size,
	const Qualifiers &quals)
{
	auto type = context.getArray(pointee, size, quals);
	if (type) {
		return type;
	}

	auto newType = std::shared_ptr<ArrayNode>(new ArrayNode(pointee, size, quals));
	context.addArrayType(newType);
	return newType;
}

unsigned ArrayNode::size() {
	return _size;
}

std::shared_ptr<Node> ArrayNode::pointee() {
	return _pointee;
}

/**
 * Prints left side of array type to output stream.
 */
void ArrayNode::printLeft(std::ostream &s) const
{
	_pointee->printLeft(s);
	_quals.printSpaceL(s);
}

/**
 * Prints right side of array type to output stream.
 */
void ArrayNode::printRight(std::ostream &s) const
{
	s << "[" << _size << "]";
	_pointee->printRight(s);
}

/**
 * @brief Private constructor for function types. Use create().
 */
FunctionTypeNode::FunctionTypeNode(
	retdec::demangler::borland::CallConv callConv,
	std::shared_ptr<retdec::demangler::borland::NodeArray> params,
	std::shared_ptr<retdec::demangler::borland::TypeNode> retType,
	retdec::demangler::borland::Qualifiers &quals,
	bool isVarArg) :
	TypeNode(quals), _callConv(callConv), _params(std::move(params)), _retType(std::move(retType)), _isVarArg(isVarArg)
{
	_kind = Kind::KFunctionType;
	_has_right = true;
}

/**
 * @brief Function for creating function types.
 * @param callConv Calling convention.
 * @param params Node representing parameters.
 * @param retType Return type, can be nullptr.
 * @param quals Function qualifiers.
 * @param isVarArg wheater function is varidic.
 * @return Node representing function type.
 */
std::shared_ptr<FunctionTypeNode> FunctionTypeNode::create(
	retdec::demangler::borland::CallConv callConv,
	std::shared_ptr<retdec::demangler::borland::NodeArray> params,
	std::shared_ptr<retdec::demangler::borland::TypeNode> retType,
	retdec::demangler::borland::Qualifiers &quals,
	bool isVarArg)
{
	return std::shared_ptr<FunctionTypeNode>(new FunctionTypeNode(callConv, params, retType, quals, isVarArg));
}

CallConv FunctionTypeNode::callConv()
{
	return _callConv;
}

std::shared_ptr<NodeArray> FunctionTypeNode::params()
{
	return _params;
}

std::shared_ptr<TypeNode> FunctionTypeNode::retType()
{
	return _retType;
}

bool FunctionTypeNode::isVarArg()
{
	return _isVarArg;
}

/**
 * Prints left side of function type to output stream.
 */
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
	case CallConv::fastcall:
		s << "__fastcall ";
		break;
	case CallConv::stdcall:
		s << "__stdcall ";
		break;
	default:
		break;
	}
}

/**
 * Prints right side of function type to output stream.
 */
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

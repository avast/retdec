/**
 * @file src/demangler_llvm/borland_ast.cpp
 * @brief Implementation of syntactic tree for borland demangler.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#include <sstream>
#include <map>

#include "llvm/Demangle/borland_ast.h"

namespace retdec {
namespace demangler {
namespace borland {

/**
 * @brief Abstract constructor for base node.
 * @param kind Kind of node.
 */
Node::Node(Kind kind, bool has_right_side) :
	_kind(kind), _has_right(has_right_side) {}

/**
 * @brief Prints left side of node.
 * @param s output stream
 */
void Node::print(std::ostream &s)
{
	printLeft(s);
	if (_has_right) {
		printRight(s);
	}
}

/**
 * @return String representation of node.
 */
std::string Node::str()
{
	std::stringstream ss;
	print(ss);
	return ss.str();
}

/**
 * @return Kind of node.
 */
Node::Kind Node::kind()
{
	return _kind;
}

/**
 * @brief Some nodes need special trailing characters.
 * @param s output stream.
 */
void Node::printRight(std::ostream &s) {}

std::unique_ptr<Node> TypeFactory::createVoid()
{
	return BuiltInType::create("void");
}

std::unique_ptr<Node> TypeFactory::createBool()
{
	return BuiltInType::create("bool");
}

std::unique_ptr<Node> TypeFactory::createWChar()
{
	return BuiltInType::create("wchar_t");
}

std::unique_ptr<Node> TypeFactory::createSignedChar()
{
	return CharType::create(CharType::Signness::signed_char);
}

std::unique_ptr<Node> TypeFactory::createChar(bool isUnsigned)
{
	if (isUnsigned) {
		return CharType::create(CharType::Signness::unsigned_char);
	} else {
		return CharType::create(CharType::Signness::not_stated);
	}
}

std::unique_ptr<Node> TypeFactory::createShort(bool isUnsigned)
{
	return IntegralType::create("short", isUnsigned);
}

std::unique_ptr<Node> TypeFactory::createInt(bool isUnsigned)
{
	return IntegralType::create("int", isUnsigned);
}

std::unique_ptr<Node> TypeFactory::createLong(bool isUnsigned)
{
	return IntegralType::create("long", isUnsigned);
}

std::unique_ptr<Node> TypeFactory::createLongLong(bool isUnsigned)
{
	return IntegralType::create("long long", isUnsigned);
}

std::unique_ptr<Node> TypeFactory::createFloat()
{
	return FloatType::create("float");
}

std::unique_ptr<Node> TypeFactory::createDouble()
{
	return FloatType::create("double");
}

std::unique_ptr<Node> TypeFactory::createLongDouble()
{
	return FloatType::create("long double");
}

/**
 * @brief Private constructor for built-in type nodes. Use create().
 * @param typeName Representation of type name.
 */
BuiltInType::BuiltInType(const StringView &typeName) :
	Node(Kind::KBuiltInType), _typeName{typeName} {}
/**
 * @brief Creates unique pointer to built-in type nodes.
 * @param typeName Representation of type name.
 * @return Unique pointer to built-in type nodes.
 */
std::unique_ptr<BuiltInType> BuiltInType::create(const StringView &typeName)
{
	return std::unique_ptr<BuiltInType>(new BuiltInType(typeName));
}

/**
 * @brief Prints string representation of built-in type.
 * @param s Output stream.
 */
void BuiltInType::printLeft(std::ostream &s)
{
	s << std::string{_typeName.begin(), _typeName.size()};
}

IntegralType::IntegralType(const StringView &typeName, bool isUnsigned) :
	BuiltInType(typeName), _isUnsigned(isUnsigned)
{
	_kind = Kind::KIntegralType;
};

std::unique_ptr<IntegralType> IntegralType::create(const StringView &typeName, bool isUnsigned)
{
	return std::unique_ptr<IntegralType>(new IntegralType(typeName, isUnsigned));
}

void IntegralType::printLeft(std::ostream &s) {
	if (_isUnsigned) {
		s << "unsigned ";
	}
	s << std::string{_typeName.begin(), _typeName.size()};
}

CharType::CharType(retdec::demangler::borland::CharType::Signness signness):
	BuiltInType("char"), _signness(signness)
{
	_kind = Kind::KCharType;
}

std::unique_ptr<CharType> CharType::create(Signness signess)
{
	return std::unique_ptr<CharType>(new CharType(signess));
}

void CharType::printLeft(std::ostream &s)
{
	switch (_signness) {
	case Signness::signed_char:
		s << "signed char";
		break;
	case Signness::unsigned_char:
		s<< "unsigned char";
		break;
	case Signness::not_stated:
		s<< "char";
		break;
	}
}

FloatType::FloatType(const StringView &typeName): BuiltInType(typeName)
{
	_kind = Kind::KFloatType;
}

std::unique_ptr<FloatType> FloatType::create(const StringView &typeName)
{
	return std::unique_ptr<FloatType>(new FloatType(typeName));
}

PointerType::PointerType(std::unique_ptr<retdec::demangler::borland::Node> pointee) :
	Node(Kind::KPointerType), _pointee(std::move(pointee)) {}

std::unique_ptr<PointerType> PointerType::create(std::unique_ptr<retdec::demangler::borland::Node> pointee)
{
	return std::unique_ptr<PointerType>(new PointerType(std::move(pointee)));
}

void PointerType::printLeft(std::ostream &s)
{
	_pointee->print(s);
	s << " *";
}

/**
 * @brief Private function node constructor. Use create().
 * @param call_conv Pointer to calling convention.
 * @param name Pointer to Name or NestedName node.
 * @param params Pointer to parameters.
 */
FunctionNode::FunctionNode(
	std::unique_ptr<retdec::demangler::borland::Node> name,
	CallConv call_conv,
	std::unique_ptr<retdec::demangler::borland::Node> params) :
	Node(Kind::KFunction, false),
	_call_conv(call_conv),
	_name(std::move(name)),
	_params(std::move(params)) {}

/**
 * @brief Creates unique pointer to function node.
 * @param call_conv Pointer to calling convention node.
 * @param name Pointer to Name or NestedName node.
 * @param params Pointer to parameters.
 * @return Unique pointer to constructed FunctionNode.
 */
std::unique_ptr<FunctionNode> FunctionNode::create(
	std::unique_ptr<retdec::demangler::borland::Node> name,
	CallConv call_conv,
	std::unique_ptr<Node> params)
{
	return std::unique_ptr<FunctionNode>(
		new FunctionNode(std::move(name), call_conv, std::move(params)));
}

/**
 * @brief Prints text representation of function.
 * @param s Output stream.
 */
void FunctionNode::printLeft(std::ostream &s)
{
	switch (_call_conv) {
	case CallConv::fastcall: s << "__fastcall ";
		break;
	case CallConv::stdcall: s << "__stdcall ";
		break;
	default: break;
	}

	_name->print(s);
	s << "(";
	if (_params) {
		_params->print(s);
	}
	s << ")";
}

/**
 * @brief Constructor for NameNode
 * @param name StringView representation of name.
 */
NameNode::NameNode(const StringView &name) : Node(NameNode::Kind::KName, false), _name(name) {}

/**
 * @param name StringView representation of name.
 * @return Unique pointer to new NameNode
 */
std::unique_ptr<NameNode> NameNode::create(const StringView &name)
{
	return std::unique_ptr<NameNode>(new NameNode(name));
}

/**
 * @brief Prints left side of node represention.
 * @param s output stream
 */
void NameNode::printLeft(std::ostream &s)
{
	s << std::string{_name.begin(), _name.size()};
}

/**
 * NestedName constructor.
 * @param super Higher level node.
 * @param name Lower level node.
 */
NestedNameNode::NestedNameNode(
	std::unique_ptr<Node> super, std::unique_ptr<Node> name) :
	Node(NameNode::Kind::KNestedName, false), _super(std::move(super)), _name(std::move(name)) {}

/**
 * @param super Higher level node.
 * @param name Lower level node.
 * @return Unique pointer to new nested name node.
 */
std::unique_ptr<NestedNameNode> NestedNameNode::create(
	std::unique_ptr<Node> super, std::unique_ptr<Node> name)
{
	return std::unique_ptr<NestedNameNode>(new NestedNameNode(std::move(super), std::move(name)));
}

/**
 * @brief Prints left side of node represention.
 * @param s output stream
 */
void NestedNameNode::printLeft(std::ostream &s)
{
	_super->print(s);
	s << std::string{"::"};
	_name->print(s);
}

/**
 * @brief Private constructor for NodeArray. Use create().
 */
NodeArray::NodeArray() : Node(Kind::KNodeArray), _nodes() {}

/**
 * @brief Creates unique pointer to new NodeArray object.
 * @return Pointer to empty ArrayNode.
 */
std::unique_ptr<NodeArray> NodeArray::create()
{
	return std::unique_ptr<NodeArray>(new NodeArray());
}

/**
 * @brief Appends new node to array.
 * @param node Node to be added.
 */
void NodeArray::addNode(std::unique_ptr<retdec::demangler::borland::Node> node)
{
	_nodes.push_back(std::move(node));
}

bool NodeArray::empty()
{
	return _nodes.empty();
}

/**
 * @brief Prints text representaion of array.
 * @param s Output stream.
 */
void NodeArray::printLeft(std::ostream &s)
{
	if (!_nodes.empty()) {
		/* print first */
		auto current = _nodes.begin();
		(*current)->print(s);

		/* print others */
		while (++current != _nodes.end()) {
			s << ", ";
			(*current)->print(s);
		}
	}
}

}    // borland
}    // demangler
}    // retdec

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

/**
 * @brief Private constructor for built-in type nodes. Use create().
 * @param typeName Representation of type name.
 */
BuiltInType::BuiltInType(const StringView &typeName) :
	Node(Kind::KBuiltIn), _typeName{typeName} {}

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

/**
 * @brief Calling convention node private constructor. Use create().
 * @param conv Calling convention.
 * @param has_right Weather the space after calling convention should be printed.
 */
CallConv::CallConv(CallConv::Conventions &conv, bool has_right) :
	Node(Kind::KCallConv, has_right), _conv(conv) {}

/**
 * @brief Creates unique pointer to CallConv node.
 * @param conv Calling convention.
 * @return Unique pointer to CallConv node.
 */
std::unique_ptr<CallConv> CallConv::create(Conventions &conv)
{
	bool has_rhs = conv == Conventions::unknown;
	return std::unique_ptr<CallConv>(new CallConv(conv, has_rhs));
}

/**
 * @return Call convention type.
 */
CallConv::Conventions CallConv::conv()
{
	return _conv;
}

/**
 * @brief Prints string representation of calling convention into ostream s.
 * @param s Output stream.
 */
void CallConv::printLeft(std::ostream &s)
{
	std::map<Conventions, std::string> to_str{
		{Conventions::stdcall, "__stdcall"},
		{Conventions::fastcall, "__fastcall"},
		{Conventions::cdecl, "__cdecl"},
		{Conventions::pascal, "__pascal"},
		{Conventions::unknown, ""}
	};

	s << to_str[_conv];
}

/**
 * @brief Prints space after calling convention.
 * @param s Output stream.
 */
void CallConv::printRight(std::ostream &s)
{
	s << " ";
}

/**
 * @brief Private function node constructor. Use create().
 * @param call_conv Pointer to calling convention.
 * @param name Pointer to Name or NestedName node.
 * @param params Pointer to parameters.
 */
FunctionNode::FunctionNode(
	std::unique_ptr<retdec::demangler::borland::CallConv> call_conv,
	std::unique_ptr<retdec::demangler::borland::Node> name,
	std::unique_ptr<retdec::demangler::borland::Node> params) :
	Node(Kind::KFunction, false),
	_call_conv(std::move(call_conv)),
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
	std::unique_ptr<retdec::demangler::borland::CallConv> call_conv,
	std::unique_ptr<retdec::demangler::borland::Node> name,
	std::unique_ptr<retdec::demangler::borland::Node> params)
{
	return std::unique_ptr<FunctionNode>(
		new FunctionNode(std::move(call_conv), std::move(name), std::move(params)));
}

/**
 * @brief Prints text representation of function.
 * @param s Output stream.
 */
void FunctionNode::printLeft(std::ostream &s)
{
	if (_call_conv->conv() != CallConv::Conventions::unknown) {
		_call_conv->print(s);
		s << " ";
	}
	_name->print(s);
	s << "(";
	_params->print(s);
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

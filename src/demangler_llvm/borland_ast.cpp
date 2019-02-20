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
void Node::print(std::ostream &s) const
{
	printLeft(s);
	if (_has_right) {
		printRight(s);
	}
}

/**
 * @return String representation of node.
 */
std::string Node::str() const
{
	std::stringstream ss;
	print(ss);
	return ss.str();
}

/**
 * @return Kind of node.
 */
Node::Kind Node::kind() const
{
	return _kind;
}

/**
 * @brief Some nodes need special trailing characters.
 * @param s output stream.
 */
void Node::printRight(std::ostream &s) const {}

bool Node::hasRight()
{
	return _has_right;
}

/**
 * @brief Private function node constructor. Use create().
 * @param call_conv Pointer to calling convention.
 * @param name Pointer to Name or NestedName node.
 * @param params Pointer to parameters.
 */
FunctionNode::FunctionNode(
	std::shared_ptr<retdec::demangler::borland::Node> name,
	CallConv call_conv,
	std::shared_ptr<retdec::demangler::borland::Node> params,
	std::shared_ptr<Node> retType,
	bool isVolatile,
	bool isConst) :
	Node(Kind::KFunction, false),
	_call_conv(call_conv),
	_name(name),
	_params(params),
	_retType(retType),
	_isVolatile(isVolatile),
	_isConst(isConst) {}

/**
 * @brief Creates shared pointer to function node.
 * @param call_conv Pointer to calling convention node.
 * @param name Pointer to Name or NestedName node.
 * @param params Pointer to parameters.
 * @return Unique pointer to constructed FunctionNode.
 */
std::shared_ptr<FunctionNode> FunctionNode::create(
	std::shared_ptr<retdec::demangler::borland::Node> name,
	CallConv call_conv,
	std::shared_ptr<Node> params,
	std::shared_ptr<Node> retType,
	bool isVolatile,
	bool isConst)
{
	return std::shared_ptr<FunctionNode>(new FunctionNode(name, call_conv, params, retType, isVolatile, isConst));
}

/**
 * @brief Prints text representation of function.
 * @param s Output stream.
 */
void FunctionNode::printLeft(std::ostream &s) const
{
	if (_retType) {
		_retType->print(s);
		s << " ";
	}

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

	if (_isVolatile) {
		s << " volatile";
	}
	if (_isConst) {
		s << " const";
	}
}

TemplateNode::TemplateNode(
	std::shared_ptr<retdec::demangler::borland::Node> name,
	std::shared_ptr<retdec::demangler::borland::Node> params) :
	Node(Kind::KTemplateNode), _name(name), _params(params) {}

std::shared_ptr<TemplateNode> TemplateNode::create(
	std::shared_ptr<retdec::demangler::borland::Node> name,
	std::shared_ptr<retdec::demangler::borland::Node> params)
{
	// TODO context
	return std::shared_ptr<TemplateNode>(new TemplateNode(name, params));
}

void TemplateNode::printLeft(std::ostream &s) const
{
	_name->print(s);
	s << "<";
	if (_params) {
		_params->print(s);
	}
	s << ">";
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
std::shared_ptr<NameNode> NameNode::create(const StringView &name)
{
	return std::shared_ptr<NameNode>(new NameNode(name));
}

/**
 * @brief Prints left side of node represention.
 * @param s output stream
 */
void NameNode::printLeft(std::ostream &s) const
{
	s << std::string{_name.begin(), _name.size()};
}

/**
 * NestedName constructor.
 * @param super Higher level node.
 * @param name Lower level node.
 */
NestedNameNode::NestedNameNode(
	std::shared_ptr<Node> super, std::shared_ptr<Node> name) :
	Node(NameNode::Kind::KNestedName, false), _super(super), _name(name) {}

/**
 * @param super Higher level node.
 * @param name Lower level node.
 * @return Unique pointer to new nested name node.
 */
std::shared_ptr<NestedNameNode> NestedNameNode::create(
	std::shared_ptr<Node> super, std::shared_ptr<Node> name)
{
	return std::shared_ptr<NestedNameNode>(new NestedNameNode(super, name));
}

/**
 * @brief Prints left side of node represention.
 * @param s output stream
 */
void NestedNameNode::printLeft(std::ostream &s) const
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
 * @brief Creates shared pointer to new NodeArray object.
 * @return Pointer to empty ArrayNode.
 */
std::shared_ptr<NodeArray> NodeArray::create()
{
	return std::shared_ptr<NodeArray>(new NodeArray());
}

/**
 * @brief Appends new node to array.
 * @param node Node to be added.
 */
void NodeArray::addNode(std::shared_ptr<retdec::demangler::borland::Node> node)
{
	_nodes.push_back(node);
}

bool NodeArray::empty() const
{
	return _nodes.empty();
}

size_t NodeArray::size()
{
	return _nodes.size();
}

/**
 * @brief Prints text representaion of array.
 * @param s Output stream.
 */
void NodeArray::printLeft(std::ostream &s) const
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

std::shared_ptr<Node> NodeArray::get(unsigned i) const
{
	return  _nodes.at(i); // TODO ked je i vacsie ako size
}

}    // borland
}    // demangler
}    // retdec
